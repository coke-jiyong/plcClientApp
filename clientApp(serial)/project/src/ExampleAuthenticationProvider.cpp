///////////////////////////////////////////////////////////////////////////////
//
//  Copyright PHOENIX CONTACT Electronics GmbH
//
///////////////////////////////////////////////////////////////////////////////
#include "Arp/System/Um/Commons/UmAuthenticationResult.hpp"
#include "include/ExampleAuthenticationProvider.hpp"
#include "include/UmModuleEx.hpp"
#include "include/UmModuleExConfig.hpp"
#include "include/verify.h"

#include "Arp/System/Rsc/Services/RscString.hxx"
#include "Arp/System/Commons/Services/Security/IDeviceIdentityValidatorService.hpp"
#include "Arp/System/Commons/Services/Security/IdentityValidationResult.hpp"
#include "Arp/System/Commons/Services/Security/IdentityValidationError.hpp"
#include "Arp/System/Rsc/ServiceManager.hpp"
using namespace Arp::System::Rsc;
using namespace Arp::System::Rsc::Services;
using namespace Arp::System::Commons::Services::Security;
using namespace std;

string error_string_std;
string error_string_arp;
IdentityValidationResult result;
namespace Arp { namespace System { namespace UmModuleEx
{
ExampleAuthenticationProvider::ExampleAuthenticationProvider(UmModuleEx& _mod) 
    : mod(_mod)
{   
    bool LicenseResult = true;
    const std::string pub_key_path = "/opt/plcnext/apps/60002172000868/pub.key";
    const std::string token_path = "/opt/plcnext/otac/license/swidchauthclient.lic";
    std::string PEM = readFileToString("/opt/plcnext/apps/60002172000868/AuthenticationProvider/certificates/certificate.pem");

    const RscString<4096> pem(PEM.c_str());
    RscString<80> id("IDevID");

    IDeviceIdentityValidatorService::Ptr ptr;
    
    try{
        ptr = ServiceManager::GetService<IDeviceIdentityValidatorService>();
        result = ptr->Validate(pem , id);
    }
    catch(Arp::Exception & e){
        //log.Debug("OTACLicenseCheck: Arp::Exception=[ {0} ]" , e.GetMessage());
        error_string_arp = e.GetMessage().CStr();
        LicenseResult = false;
    }

    if(result.Error != IdentityValidationError::None) {
        LicenseResult = false;
    }

    char * serialNumber = result.SubjectSerialNumber.CStr();
    checkLicense handle(pub_key_path, token_path);

    try{
        handle.init();
        handle.validateHostId(serialNumber);
    }
    catch(std::runtime_error & e){
        //log.Debug("OTACLicenseCheck: std::runtime_error=[ {0} ]" , e.what());
        error_string_std = e.what();
        LicenseResult = false;
    }

    if(LicenseResult == false) {
        mod.licenseCheckFail();
    }
    
    
}

UmAuthenticationResult ExampleAuthenticationProvider::AuthenticateUser(const String& username,
        const String& password, SessionInfo& sessionInfo)
{   
    if (!mod.Started()) 
    {
        return UmAuthenticationResult::Failed;
    }
    if(!mod.UserAuthStarted()){
        log.PrintDebug("OTACAuthenticationProvider: License check failed");
        if(!error_string_std.empty()) {
            log.Debug("--- {0}",error_string_std);
        }
        if(!error_string_arp.empty()) {
            log.Debug("--- {0}",error_string_arp);
        }
        if (result.Error != IdentityValidationError::None) {
            log.Debug("--- {0}",result.Error);
        }
        return UmAuthenticationResult::Failed;
    }

    log.Debug("OTACAuthenticationProvider: License check success.");
    const UserConfTag& userconf = mod.GetConfig()->userConf;
    Verify handler(password.CStr());    
#if 1
    if( !handler.Set_Host_IP() ) {
        log.Debug("OTACAuthenticationProvider: Set_Host_IP failed.");
        return UmAuthenticationResult::Failed;
    }
#endif
    handler.Set_Post(userconf.url.CStr()); 
    handler.Request();
    Json::Value root = handler.Get_Root(); 

#if 1
    log.Debug("OTACAuthenticationProvider: Host Address : {0}" , handler.Get_Ip());
#endif
    log.Debug("OTACAuthenticationProvider: Server Address : {0}" , userconf.url.CStr());
    log.Debug("OTACAuthenticationProvider: {0}" , handler.Get_Response());
    
   return result_check(root, username, sessionInfo);
}

UmAuthenticationResult ExampleAuthenticationProvider::result_check(Json::Value Root, const String& inputUser , SessionInfo& sessionInfo)
{
    const char * username = inputUser.CStr();
    if (Root["userId"] == username){
        if (Root["result"] == "SUCCESS"){  
            list<String> roles;       
            String Roles(Root["userRoles"].asCString());
            if (Roles.Find('|') != -1){  
                vector<string> result = split(Roles, '|');

                for(int i = 0 ; i < result.size() ; i ++) {
                    roles.push_back(result[i]);
                }
                sessionInfo.SetRoles(roles);
                for(auto i : result) {
                    i.clear();
                }
                vector<string>().swap(result);
                result.clear();
                for(auto i : roles) {
                    i.Clear();
                }
                list<String>().swap(roles);
                roles.clear();
                return UmAuthenticationResult::Success;
            }
            roles = {Roles};
            sessionInfo.SetRoles(roles);   
            std::list<String>().swap(roles);   
            roles.clear();      
            return UmAuthenticationResult::Success;
        }
        else{   
            return UmAuthenticationResult::WrongPassword;
        }
    }
    return UmAuthenticationResult::Failed;    
}


void ExampleAuthenticationProvider::OnSessionClose(SessionInfo& session)
{
    String clientIpAdress;
    String accessToken;
    log.Debug("ExampleAuthenticationProvider: session closed, id={0}, session holding lock={1}, clientIp={2}, accessToken={3}, protocolObjName={4}, user={5}",
             session.GetSecurityToken(), mod.GetLockedSession(), clientIpAdress, accessToken, session.GetProtocolObjName(), session.GetUserName());

    mod.UnlockSession(session);
}

}}} // end of namespace Arp::System::UmModuleEx
