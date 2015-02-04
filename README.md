=======================================================================================================
This is a standard xrootd Acc library plugin.

You can enable it for the Ofs library including the following tags into your xrootd configuration file:
-------------------------------------------------------------------------------------------------------

ofs.authlib /opt/xrootd/lib/libXrdAliceTokenAcc.so
ofs.authorize

-------------------------------------------------------------------------------------------------------

To enable debugging on the fly, create the file:

/tmp/XrdAliceTokenDebug

To disable debugging on the fly, remove the file:
/tmp/XrdAliceTokenDebug

-------------------------------------------------------------------------------------------------------
