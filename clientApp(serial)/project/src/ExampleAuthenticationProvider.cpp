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


using namespace Arp::System::Rsc;
using namespace Arp::System::Rsc::Services;
using namespace Arp::System::Commons::Services::Security;
using namespace std;
const std::string pub_key_path = "/opt/plcnext/apps/60002172000868/pub.key";
const std::string token_path = "/opt/plcnext/otac/license/swidchauthclient.lic";
const std::string PEM = readFileToString("/opt/plcnext/apps/60002172000868/AuthenticationProvider/certificates/certificate.pem");
const RscString<4096> pem(PEM.c_str());
const RscString<80> id("IDevID");
static IdentityValidationResult result;
namespace Arp { namespace System { namespace UmModuleEx
{
std::string ExampleAuthenticationProvider::error_msg = "";
ExampleAuthenticationProvider::ExampleAuthenticationProvider(UmModuleEx& _mod) 
    : mod(_mod)
{  
    bool LicenseResult = true;
    IDeviceIdentityValidatorService::Ptr ptr = ServiceManager::GetService<IDeviceIdentityValidatorService>();
    result = ptr->Validate(pem , id);
    if(result.Error != IdentityValidationError::None) {
        LicenseResult = false;
    }
    else {
        char * serialNumber = result.SubjectSerialNumber.CStr();
        checkLicense handle(pub_key_path, token_path);

        try{
            handle.init();
            handle.validateHostId(serialNumber);
        }
        catch(std::runtime_error & e){
            //log.Debug("OTACLicenseCheck: std::runtime_error=[ {0} ]" , e.what());
            ExampleAuthenticationProvider::error_msg = e.what();
            LicenseResult = false;
        }
    }
    

    if(LicenseResult == false) {
        mod.licenseCheckFail();
    }
}

UmAuthenticationResult ExampleAuthenticationProvider::AuthenticateUser(const String& username,
        const String& password, SessionInfo& sessionInfo)
{   
    if (!mod.Started()) {
        return UmAuthenticationResult::Failed;
    }
    if(!mod.UserAuthStarted()) {
        log.PrintDebug("OTACAuthenticationProvider: License check failed");
        this->print_error();
        return UmAuthenticationResult::Failed;
    }

    log.Debug("OTACAuthenticationProvider: License check success.");
    const UserConfTag& userconf = mod.GetConfig()->userConf;
    Verify handler(password.CStr());    

    if( !handler.Set_Host_IP() ) {
        log.Debug("OTACAuthenticationProvider: Set_Host_IP failed.");
        return UmAuthenticationResult::Failed;
    }

    handler.Set_Post(userconf.url.CStr()); 
    handler.Request();
    Json::Value root = handler.Get_Root(); 

#if 1
    log.Debug("OTACAuthenticationProvider: Host Address : {0}" , handler.Get_Ip());
    log.Debug("OTACAuthenticationProvider: Server Address : {0}" , userconf.url.CStr());
    log.Debug("OTACAuthenticationProvider: {0}" , handler.Get_Response());
#endif    
    
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
                
                return UmAuthenticationResult::Success;
            }
            roles = {Roles};
            sessionInfo.SetRoles(roles);   
            
            return UmAuthenticationResult::Success;
        }
        else{   
            return UmAuthenticationResult::WrongPassword;
        }
    }
    return UmAuthenticationResult::Failed;    
}

void ExampleAuthenticationProvider::print_error() const{
    
    if (result.Error != IdentityValidationError::None) {
        log.Debug("--- {0}", result.Error);
    }
    if (!ExampleAuthenticationProvider::error_msg.empty()) {
        log.Debug("--- {0}", ExampleAuthenticationProvider::error_msg);
    }
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
