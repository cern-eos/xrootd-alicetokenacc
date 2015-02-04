//         $Id: XrdAliceTokenAcc.cc,v 1.13 2007/10/04 01:34:19 abh Exp $

#include "XrdOuc/XrdOucTrace.hh"
#include "XrdOuc/XrdOucEnv.hh"
#include "XrdSys/XrdSysError.hh"
#include "XrdSec/XrdSecEntity.hh"
#include "XrdOuc/XrdOucString.hh"
#include "XrdOuc/XrdOucStream.hh"

#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/hmac.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>

#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/engine.h>
#include <openssl/sha.h>

#include <TTokenAuthz.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <iostream>
#include <fstream>
#include <netinet/in.h>

#include "XrdVersion.hh"
XrdVERSIONINFO(XrdAccAuthorizeObject,"AliceTokenAcc");

XrdSysError TkEroute(0,"AliceTokenAcc");
XrdOucTrace TkTrace(&TkEroute);

#include "XrdAliceTokenAcc/XrdAliceTokenAcc.hh"

XrdOucHash<XrdOucString>*  XrdAliceTokenAcc::NoAuthorizationHosts;
XrdOucTList*               XrdAliceTokenAcc::NoAuthorizationHostWildcards;
XrdOucString               XrdAliceTokenAcc::TruncatePrefix="";
XrdSysMutex*               XrdAliceTokenAcc::CryptoMutexPool[128];
EVP_PKEY*                  XrdAliceTokenAcc::EVP_RemotePublicKey;
#define IS_SLASH(s) (s == '/')


/******************************************************************************/
/*             T h r e a d - S a f e n e s s   F u n c t i o n s              */
/******************************************************************************/
static unsigned long aliceauthzssl_id_callback(void) {
  return (unsigned long)XrdSysThread::ID();
}

void aliceauthzssl_lock(int mode, int n, const char *file, int line)
{
  if (mode & CRYPTO_LOCK) {
    if (XrdAliceTokenAcc::CryptoMutexPool[n]) {
      XrdAliceTokenAcc::CryptoMutexPool[n]->Lock();
    }
  } else {
    if (XrdAliceTokenAcc::CryptoMutexPool[n]) {
      XrdAliceTokenAcc::CryptoMutexPool[n]->UnLock();
    }
  }
}

bool
XrdAliceTokenAcc::MatchWildcard(const char* host) {
  XrdOucTList* lp=NoAuthorizationHostWildcards;

  while (lp) {
    XrdOucString match = host;
    XrdOucString pattern = lp->text;
    
    // check for ? matches
    if (pattern.find('?')!= STR_NPOS) {
      int pos=0;
      while ( (pos = pattern.find('?',pos)) != STR_NPOS) {
	if (pos <= match.length()) {
	  match.erase(pos,pos+1);
	  match.insert('?',pos);
	}
      }
      if (match == host) {
	return true;
      }
      lp = lp->next;
      continue;
    }

    if (pattern.find('*')!=STR_NPOS) {
      XrdOucString startswith;
      XrdOucString stopswith;
      startswith.assign(pattern,0, pattern.find('*')-1);
      stopswith.assign(pattern, pattern.find('*')+1);
      if (debug) { 
	TkTrace.Beg("Match");
	cerr <<"Match by '*': Startswith " << startswith.c_str() << " Stopswith " <<stopswith.c_str();
	TkTrace.End();
      }
      if ( match.beginswith(startswith) && match.endswith(stopswith) ) {
	return true;
      }
    }

    int n1,n2,n3;
    n1=n2=n3=0;
    if ( ((n1=pattern.find('[')) !=STR_NPOS) && ((n2=pattern.find(']')) != STR_NPOS) ) {
      int a,b,c;
      a=b=c=0;
      XrdOucString sa,sb,sc; 
      if (debug) { 
	TkTrace.Beg("Match");
	cerr <<"Match by '[a-b]': n1 " << n1 << " n2 " << n2;
	TkTrace.End();
      }
      if (n1 < n2) {
	n3 = pattern.find('-',n1+1);
	
	if ( (n3>n1) && (n3 < n2) ) {
	  sa.assign(pattern,n1+1,n3-1);
	  sb.assign(pattern,n3+1,n2-1);
	  a = atoi(sa.c_str());
	  b = atoi(sb.c_str());

	  XrdOucString startswith;
	  XrdOucString stopswith;
	  startswith.assign(pattern,0, pattern.find('[')-1);
	  stopswith.assign(pattern, pattern.find(']')+1);

	  if (debug) { 
	    TkTrace.Beg("Match");
	    cerr <<"Match by '[a-b]': Startswith " << startswith.c_str() << " Stopswith " <<stopswith.c_str();
	    TkTrace.End();
	  }
	  if ( match.beginswith(startswith) && match.endswith(stopswith) ) {
	    // see the number in the host
	    if ( (n3-1) < match.length()) {
	      sc.assign(match,n1,n3-2);
	      ErrnoMutex.Lock();
	      errno = 0;
	      c = (int) strtol(sc.c_str(),NULL,0);
	      if (debug) { 
		TkTrace.Beg("Match");
		cerr <<"Match by '[a-b]': Converted " << sc.c_str() << " to " << c;
		TkTrace.End();
	      }


	      if (errno != 0) {
		ErrnoMutex.UnLock();
		lp = lp->next;
		continue;
	      }
	      ErrnoMutex.UnLock();
	      if ( (a <= c) && (c <= b) ) {
		return true;
	      }
	    }
	  }
	}
      }
    }
    lp = lp->next;
  }
  return false;
}


XrdAccPrivs 
XrdAliceTokenAcc::Access(const XrdSecEntity    *client,
			 const char            *path,
			 const Access_Operation oper,
			 XrdOucEnv             *Opaque) 
{
  TAuthzXMLreader* authz=0;
  int envlen ;
  
  XrdOucString UnprefixedPath="";
  XrdOucString sopaque = "";

  const char* opaque = "";

  if (Opaque) {
    // we have to remove all double quotes - it is convenient to allow double quotes to pass opaque information via shell commands
    sopaque = Opaque->Env(envlen);
    while (sopaque.replace("\"","")) {}
    opaque = sopaque.c_str();
  }

  std::map<std::string,std::string> env;

  TTokenAuthz::Tokenize(opaque,env,"&");


  XrdOucString protocol = client->prot;

  // trusted machines can do anything!
  if (protocol == "sss") {
    return XrdAccPriv_All;
  }
  if (protocol == "krb5") {
    return XrdAccPriv_All;
  }
  if (protocol == "gsi") {
    return XrdAccPriv_All;
  }

  if ( env["signature"].length() > 0 ) {

    // set the opening mode
    std::string authzopenmode="";

    switch(oper) { 
    case AOP_Create :
    case AOP_Update:
      authzopenmode="write";
      break;
    case AOP_Delete:
      authzopenmode="delete";
      break;
    case AOP_Read :
      authzopenmode="read";
      break; 
    case AOP_Stat :
      return XrdAccPriv_Lookup;
    case AOP_Readdir :
      return XrdAccPriv_Readdir;
    default:
      return XrdAccPriv_None;
    }
    
    
    if ( env["hashord"].length() > 0) { 
      // ok!
    } else {
      // no priviledges at all!
      fprintf(stderr, "invalid hashorder\n");
      return XrdAccPriv_None;
    }
    

    if (debug) {
      TkTrace.Beg("Access");
      cerr <<"Hashorder "<< env["hashord"].c_str();
      TkTrace.End();
    }

    std::string verify= "";
    std::map<std::string,std::string> keys;
    
    std::string str=env["hashord"].c_str();
    std::string delimiters = "-";
    
    // Skip delimiters at beginning.
    std::string::size_type lastPos = str.find_first_not_of(delimiters, 0);
    // Find first "non-delimiter".
    std::string::size_type pos     = str.find_first_of(delimiters, lastPos);
    
    while (std::string::npos != pos || std::string::npos != lastPos) {
      // Found a token, add it to the map.
      std::string tokenstring = str.substr(lastPos, pos - lastPos);
      
      verify += ( tokenstring + "=" + env[tokenstring] + "&");
      
      // Skip delimiters.  Note the "not_of"
      lastPos = str.find_first_not_of(delimiters, pos);
      // Find next "non-delimiter"
      pos = str.find_first_of(delimiters, lastPos);
    }
    
    if (verify.length()) verify.erase(verify.length()-1,1);	
    
    if (debug) {
      TkTrace.Beg("Access");
      fprintf (stderr, "sign string: %s, signature %s ", verify.c_str(), env["signature"].c_str());
      TkTrace.End();
    }
    
    const char* remotepublickey= "/home/ali/.authz/xrootd/pubkey.pem";
    std::string fRemotePublicKey  = std::string(remotepublickey);
    
    EVP_PKEY*  fEVP_RemotePublicKey  = ReadPublicKey(fRemotePublicKey.c_str());
    
    // build the sha384 hash
    uint_fast8_t hash[48];
    
#ifdef SHA384_DIGEST_LENGTH
    // just to make it compile, certainly won't work without sha384
    if (!SHA384( (uint_fast8_t*)verify.c_str(), (uint32_t)verify.length(), hash) ) {
#else
    if (!SHA1( (uint_fast8_t*)verify.c_str(), (uint32_t)verify.length(), hash) ) {
#endif
      fprintf(stderr,"Cannot build the sha2 hash sum!\n");
      return XrdAccPriv_None;
    }
    
    if (debug) {
      TkTrace.Beg("Access");
      fprintf(stdout,"\nsignature found, length, printout: %u, %s \n", (int)env["signature"].length(), env["signature"].c_str()); 
      TkTrace.End();
    }
    
    char* decsignature = (char*) unbase64((unsigned char*) env["signature"].c_str(), env["signature"].length());
    
    if (debug) {
      TkTrace.Beg("Access");
      fprintf(stdout,"decoded signature, length, printout: %d, %s\n" , (int)sizeof(decsignature), decsignature);
      TkTrace.End();
    } 
    
    // verify the signature of the envelope (sha384 brings up 
    int siglen = EVP_PKEY_size(fEVP_RemotePublicKey);
    
#ifdef SHA384_DIGEST_LENGTH
    int32_t verified = RSA_verify(NID_sha384, hash, 48,
				  (unsigned char*) decsignature, siglen, fEVP_RemotePublicKey->pkey.rsa);
#else
    int32_t verified = RSA_verify(NID_sha1, hash, 48,
				  (unsigned char*) decsignature, siglen, fEVP_RemotePublicKey->pkey.rsa);
#endif
    
    
    if (decsignature)
      free(decsignature); 
    
    if (verified != 1) {
      fprintf(stderr,"ERROR: The signature couldn't been verified![%d]!\n",verified);
      return XrdAccPriv_None;
    }
    
    
    time_t ex_time = atoi(env["expires"].c_str());
    char eex_time[4096];
    sprintf(eex_time,"%lu",ex_time);
    if (strcmp(env["expires"].c_str(),eex_time)) {
      fprintf(stderr,"Envelope Timestamp is illegal: |%s|%s|!\n",env["expires"].c_str(),eex_time);
      return XrdAccPriv_None;
    }
    
    time_t tdiff = (time(NULL)- ex_time);
    if ( (tdiff > 0) && (ex_time !=0) ) {
      fprintf(stderr,"Envelope has expired since %lu secondes!\n", tdiff);
      return XrdAccPriv_None;
    }
    
    // size, md5
    
    if (strcmp(env["access"].c_str(),authzopenmode.c_str())) {
      fprintf(stderr,"The specified access mode is not granted in the signed Envelope [%s != %s] .\n", env["access"].c_str(),authzopenmode.c_str());
      return XrdAccPriv_None;
    }
    
    XrdOucString cpath=env["turl"].c_str();
    int dspos = cpath.rfind("//"); 
    if (dspos != STR_NPOS) {
      cpath.erase(0,dspos+1);
    } 
    
    if (strcmp(cpath.c_str(),path)) {
      fprintf(stderr,"The specified path is not granted in the signed Envelope [%s != %s] .\n", cpath.c_str(), path);
      return XrdAccPriv_None;
    }
       
    if (debug) {
      TkTrace.Beg("Access");
      fprintf(stdout,"Signature verified. All fine!\n");
      TkTrace.End();
    }  
    // 
    return XrdAccPriv_All;
  } else {
    // see if we have to erase some prefix
    if (TruncatePrefix.length()) {
      UnprefixedPath=path;
      UnprefixedPath.replace(TruncatePrefix.c_str(),"");
      if (!UnprefixedPath.beginswith('/')) {
	UnprefixedPath.insert('/',0);
      }
      path = UnprefixedPath.c_str();
    }
    
    std::string vo="*";
    
    // if we have the vo defined in the credentials, use this one
    if (client) {
      if ((client->vorg) && (strlen(client->vorg)))
	vo = client->vorg;
    }
    
    // set the certificate, if we have one
    const char* certsubject=0;
    if (client) {
      if ((client->name) && (strlen(client->name))) {
	certsubject = client->name;
      }
    }
    
    TTokenAuthz* tkauthz = 0;
    debug = false;
    struct stat buf;
    if (!stat("/tmp/XrdAliceTokenDebug",&buf)) {
      debug = true;
    } else {
      debug = false;
    }
    
    if (debug) {
      tkauthz = TTokenAuthz::GetTokenAuthz("xrootd",true); // with debug output
    } else {
      tkauthz = TTokenAuthz::GetTokenAuthz("xrootd",false);// no debug output
    }
    
    
    // set the opening mode
    std::string authzopenmode="";
    
    switch(oper) {
    case AOP_Create :
    case AOP_Update:
      authzopenmode="write-once";
      break;
    case AOP_Delete :
      break;
    case AOP_Read :
      authzopenmode="read";
      break;
    case AOP_Stat :
      return XrdAccPriv_Lookup;
    case AOP_Readdir :
      return XrdAccPriv_Readdir;
    default:
      return XrdAccPriv_None;
    }
    
    // allow the quick route ... e.g. check if we can grant an operation without decoding the envelope
    
    // check if the directory asked is exported
    if (tkauthz->PathIsExported(path,vo.c_str(),certsubject)) {
      // check the host
      if (client) {
	if (client->host) {
	  // if this is a authorization free host, allow it!
	  if (NoAuthorizationHosts->Find(client->host)) {
	    return XrdAccPriv_All;
	  }
	  if (MatchWildcard(client->host)) 
	    return XrdAccPriv_All;
	}
      }   
      if (!tkauthz->PathHasAuthz(path,authzopenmode.c_str(),vo.c_str(),certsubject)) {
	// the pass through
	return XrdAccPriv_All;
      } else {
	if ( ((env["authz"].length()) == 0 ) || (env["authz"] == "alien") || (env["authz"] == "alien?")) {
	  // path needs authorization
	  TkEroute.Emsg("Access",EACCES,"give access for lfn - path has to be authorized",path);
	  return XrdAccPriv_None;
	}
      }
    } else {
      // path is not exported for this VO
      TkEroute.Emsg("Access",EACCES,"give access for lfn - path not exported",path);
      return XrdAccPriv_None;
    }
    
    int garesult=0;
    float t1,t2;
    
    garesult = tkauthz->GetAuthz(path,opaque,&authz,debug,&t1,&t2);

    // mantain ALICE symlinks
    if ( getenv("ALICE_TOKEN_SYMLINKS") ) {
      char localpath[16384];
      //      XrdOfsOss->GenLocalPath(path, localpath);
      XrdOucString linkname = getenv("ALICE_TOKEN_SYMLINKS");
      XrdOucString linktarget=localpath;
      XrdOucString linkpointer = "";
      linkname += "/"; linkname += authz->GetKey(path,"lfn");
      struct stat buf;
      if (!stat(linkname.c_str(), &buf)) {
        char linkdestination[4096];
        if ( (readlink (linkname.c_str(), linkdestination, sizeof(linkdestination))) > 0) {
          linkpointer = linkdestination;
        }
      }

      if (linktarget != linkpointer) {
        int rc = unlink(linkname.c_str());
        if (rc) rc = 0;
        // link does not point properly
        int pos=0;
        int retc=0;
        XrdOucString newpath = linkname.c_str();
        while(newpath.replace("//","/")) {};
        int rpos=STR_NPOS;
        while ((rpos = newpath.rfind("/",rpos))!=STR_NPOS) {
          XrdOucString existspath;
          existspath.assign(newpath,0,rpos);

          if (!stat(existspath.c_str(), &buf)) {
            // this exists, now creat until the end
            int fpos= rpos+2;
            while ( (fpos = newpath.find("/",fpos)) != STR_NPOS ) {
              XrdOucString createpath;
              createpath.assign(newpath,0,fpos);
              mkdir(createpath.c_str(),S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH);
              fpos++;
            }
            break;
          }
          rpos--;
        }
        // create a link
        retc = symlink(linktarget.c_str(),linkname.c_str());
        if (retc) retc=0;
      }
    }

    if (debug) {
      TkTrace.Beg("Access");
      cerr <<"Time for Authz decoding: " << t1 << " ms" << " / " << t2 << "ms =>" << path ;
      TkTrace.End();
    }
    
    if (garesult != TTokenAuthz::kAuthzOK) {
      // if the authorization decoding failed for any reason
      TkEroute.Emsg("Access",tkauthz->PosixError(garesult),tkauthz->ErrorMsg(garesult) , path);
      if (authz) delete authz;
      return XrdAccPriv_None;
    }
    
    // check the access permissions
    if (oper == AOP_Read) {
      // check that we have the READ access
      if (strcmp(authz->GetKey((char*)path,"access"), "read")) {
	// we have no read access
	TkEroute.Emsg("Access",EACCES,"have read access for lfn" , path);
	if (authz) delete authz;
	return XrdAccPriv_None;
      }
    } else {
      if ( (oper == AOP_Create) || (oper == AOP_Stat) || (oper == AOP_Update) ) {
	// check that we have the WRITE access
	if (strcmp(authz->GetKey((char*)path,"access"), "write-once")) {
	  // we have no write-once access
	  TkEroute.Emsg("Access",EACCES,"have write access for lfn" , path);
	  if (authz) delete authz;
	  return XrdAccPriv_None;
	}
      } else {
	if ( (oper == AOP_Delete) ) {
	  // check that we have the READ-WRITE access
	  if (strcmp(authz->GetKey((char*)path,"access"), "delete")) {
	    // we have no deletion access
	    TkEroute.Emsg("Access", EACCES, "have delete access for lfn", path);
	    if (authz) delete authz;
	    return XrdAccPriv_None;
	  }
	} else {
	  TkEroute.Emsg("Access", EACCES, "have access for lfn", path);
	  if (authz) delete authz;
	  return XrdAccPriv_None;
	}
      }  
    }
    
    // get the turl
    const char* newfilename = TTokenAuthz::GetPath(authz->GetKey((char*)path,"turl"));
    std::string copyfilename = newfilename;
    
    // check if the asked filename is exported
    if (!tkauthz->PathIsExported(newfilename,vo.c_str())) {
      // path is not exported for this VO
      TkEroute.Emsg("Acess", EACCES, "give access for turl - path not exported", newfilename);
      if (authz) delete authz;
      return XrdAccPriv_None;
    }
    
    // do certifcate check, if it is required
    if (tkauthz->CertNeedsMatch(newfilename,vo.c_str())) {
      if (certsubject != authz->GetKey((char*)path,"certsubject")) {
	TkEroute.Emsg("Access", EACCES, "give access for turl - certificate subject does not match", newfilename);
	return XrdAccPriv_None;
      }
    }
    
    if (authz)delete authz;
    return XrdAccPriv_All;
  }
}

bool
XrdAliceTokenAcc::Configure(const char* ConfigFN) {
  char *var;
  const char *val;
  int  cfgFD, retc, NoGo = 0;

  NoAuthorizationHosts = new XrdOucHash<XrdOucString>();
  NoAuthorizationHostWildcards = NULL;
  TruncatePrefix = "";

  XrdOucStream Config(&TkEroute, getenv("XRDINSTANCE"));
  if( (!ConfigFN) || (!(*ConfigFN))) {
    TkEroute.Emsg("Config", "Configuration file not specified.");
    return false;
  } else {
    // Try to open the configuration file.
    //
    if ( (cfgFD = open(ConfigFN, O_RDONLY, 0)) < 0)
      return TkEroute.Emsg("Config", errno, "open config file", ConfigFN);
    Config.Attach(cfgFD);
    // Now start reading records until eof.
    //
    
    while((var = Config.GetMyFirstWord())) {
      if (!strncmp(var, "alicetokenacc.", 14)) {
        var += 14;
	if (!strcmp("noauthzhost",var)) {
          val = Config.GetWord();
	  
          TkEroute.Say("=====> alicetokenacc.noauthzhost: ", val,"");
	  if ((strchr(val,'*')) || (strchr(val,'[') && strchr(val,']')) || (strchr(val,'?'))) {
	    // add a wildcard pattern to the list
	    NoAuthorizationHostWildcards = new XrdOucTList(val, 0, NoAuthorizationHostWildcards);
	  } else {
	    NoAuthorizationHosts->Add(val,new XrdOucString(val));
	  }
        }
	if (!strcmp("truncateprefix",var)) {
	  val = Config.GetWord();
	  
	  TkEroute.Say("=====> alicetokenacc.truncateprefix: ", val,"");
	  TruncatePrefix=val;
	}
      }
    }
  }
  
  // create the crypto mutex pool

  for (size_t i=0; i< 128; i++) {
    XrdAliceTokenAcc::CryptoMutexPool[i] = new XrdSysMutex();
  }

  // set callback functions
  CRYPTO_set_locking_callback(aliceauthzssl_lock);
  CRYPTO_set_id_callback(aliceauthzssl_id_callback);
  return true;
}

bool
XrdAliceTokenAcc::Init() {
  std::list<std::string> configpaths;
  
  // find the location of the keys to sign response envelopes
  if (getenv("TTOKENAUTHZ_AUTHORIZATIONFILE")) {
    configpaths.push_back(std::string(getenv("TTOKENAUTHZ_AUTHORIZATIONFILE")));
  } else {
    fprintf(stderr,"=====> XrdAliceTokenAcc: No Authorizationfile set via environment variable 'TTOKENAUTHZ_AUTHORIZATIONFILE'\n");
  }
  
  std::string extraname = "xrootd/";
  
  configpaths.push_back("/etc/grid-security/" + extraname +"TkAuthz.Authorization");
  if (getenv("HOME")) {
    std::string pstring = getenv("HOME");
    pstring +=  "/.globus/";
    pstring += extraname;
    pstring += "TkAuthz.Authorization";
    configpaths.push_back(pstring);
    pstring = getenv("HOME");
    pstring +=  "/.authz/";
    pstring += extraname;
    pstring += "TkAuthz.Authorization";
    configpaths.push_back(pstring);
  }
  
  std::list<std::string>::iterator confname;
  
  std::string authorizationfile="";
  
  for (confname=configpaths.begin(); confname != configpaths.end(); ++confname) {
    struct stat buf;
    if (!::stat((*confname).c_str(),&buf)) {
      if ( (buf.st_mode & S_IWGRP) || (buf.st_mode & S_IWGRP) ) {
	fprintf(stderr,"=====> XrdAliceTokenAcc: Authorizationfile '%s' has insecure permission! Not used!\n",(*confname).c_str());
      } else {
	fprintf(stderr,"=====> XrdAliceTokenAcc: Using Authorizationfile '%s'!\n",(*confname).c_str());
	authorizationfile=(*confname);
	break;
      }
    } else {
      fprintf(stderr,"=====> XrdAliceTokenAcc: No Authorizationfile like '%s' found\n",(*confname).c_str());
    }
  }
  
  EVP_RemotePublicKey = 0;

  if (authorizationfile.length()) {
    char buffer[1025];
    std::ifstream authzfile(authorizationfile.c_str());
    
    while (authzfile.getline(buffer,sizeof(buffer))) {
      int length=strlen(buffer);
      // ignore comments
      if (buffer[0] == '#')
	continue;
      if (length == 0)
	continue;
      
      XrdOucString pubkey = buffer;
      
      if (pubkey.beginswith("PUBKEY:")) {
	size_t i=0;
	for (i=0; i < length; i++) {
	  if ( (buffer[i] == ' ') || (buffer[i] == '\t') || (buffer[i] == '\n') || (buffer[i] == 0) ) 
	    break;
	}
	  pubkey.erase(i);
      }
      
      fprintf(stdout, "=====> XrdAliceTokenAcc: Public key in use is %s\n", pubkey.c_str());
      EVP_RemotePublicKey  = ReadPublicKey(pubkey.c_str());
      if (!EVP_RemotePublicKey) {
	fprintf(stdout, "=====> XrdAliceTokenAcc: Cannot load public key !\n");
      }
    }
  } else {
    fprintf(stdout, "=====> XrdAliceTokenAcc: no public key - will not verify response envelopes\n");
  }
  
  debug=false;
  return true;
}

XrdAliceTokenAcc::~XrdAliceTokenAcc() {}
/* XrdAccAuthorizeObject() is called to obtain an instance of the auth object
   that will be used for all subsequent authorization decisions. If it returns
   a null pointer; initialization fails and the program exits. The args are:

   lp    -> XrdSysLogger to be tied to an XrdSysError object for messages
   cfn   -> The name of the configuration file
   parm  -> Parameters specified on the authlib directive. If none it is zero.
*/

extern "C" XrdAccAuthorize *XrdAccAuthorizeObject(XrdSysLogger *lp,
                                              const char   *cfn,
                                              const char   *parm) 
{
  TkEroute.SetPrefix("XrdAliceTokenAcc::");
  TkEroute.logger(lp);
  TkEroute.Say("++++++ (c) 2008 CERN/IT-DM-SMD ",
	       "AliceTokenAcc (Alice Token Access Authorization) v 1.0");
  XrdAccAuthorize* acc = (XrdAccAuthorize*) new XrdAliceTokenAcc();
  if (!acc) {
     TkEroute.Say("------ AliceTokenAcc Allocation Failed!");
     return 0;
  }

  if (!((XrdAliceTokenAcc*)acc)->Configure(cfn) || (!((XrdAliceTokenAcc*)acc)->Init())) {
    TkEroute.Say("------ AliceTokenAcc Initialization Failed!");
    delete acc;
    return 0;
  } else {
    TkEroute.Say("------ AliceTokenAcc initialization completed");
    return acc;
  }
}






EVP_PKEY*
XrdAliceTokenAcc::ReadPublicKey(const char* certfile) {
  FILE *fp = fopen (certfile, "r");
  X509 *x509;
  EVP_PKEY *pkey;

  if (!fp) {
     return NULL;
  }

  x509 = PEM_read_X509(fp, NULL, 0, NULL);

  if (x509 == NULL)
  {
     ERR_print_errors_fp (stderr);
     return NULL;
  }

  fclose (fp);

  pkey=X509_extract_key(x509);

  X509_free(x509);

  if (pkey == NULL)
     ERR_print_errors_fp (stderr);

  return pkey;

}


char *XrdAliceTokenAcc::unbase64(unsigned char *input, int length) {
    BIO *b64, *bmem;
    
    char *buffer = (char *)malloc(length);
    memset(buffer, 0, length);
    
    fprintf (stderr,"unbase64ing: %s, %d\n", input, length);
    
    b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bmem = BIO_new_mem_buf(input, length);
    bmem = BIO_push(b64, bmem);
    
    BIO_read(bmem, buffer, length);
    
    BIO_free_all(bmem);
    
    fprintf (stderr,"unbase64ed: %s\n", buffer);
    
    return buffer;
}




