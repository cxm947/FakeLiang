"""Developer-maintained structural cases based on the active rules5.P templates.

This is not a runtime association to a .P file and does not run Prolog.
Matching uses predicate signatures, shared variable bindings, and constraints.
Descriptions are display metadata and never determine rule identity.
Unusual source literals are intentionally preserved.
"""

from dataclasses import dataclass

from .terms import parse_fact


@dataclass(frozen=True)
class RuleCase:
    id: str
    description: str
    head: str
    body: tuple[str, ...]
    different: tuple[tuple[str, str], ...] = ()


def case(case_id, description, head, *body, different=()):
    return RuleCase(case_id, description, head, body, different)


INJECTION = "Insecure Operations Leading to Attack Vector Injection"
DIRECT = "Direct Network Access"
BRUTE = "Brute Force Password Spraying - T1110.003"
PUBLIC = "Exploit Public-Facing Application - T1190"
LSASS = "OS Credential Dumping LSASS Memory - T1003.001"
ESCALATION = "Exploitation for Privilege Escalation - T1068"
PATH = "Hijack Execution Flow Path Interception - T1574.007"
VB = "Command and Scripting Interpreter - Visual Basic - T1059.005"
WINRM = "Remote Services - Windows Remote Management - T1021.006"
WIN_CRED_REMOTE = "Remote Services - Windows Credential Remote Execution - T1021"
REMOTE = "Exploitation of Remote Services - T1210"

CASES = (
    case("vector_injection", INJECTION, "attackVectorInjection(H,Perm,Protocol,Port)",
         "attackerLocated(Zone)", "inCompetent(User,H,Perm)", "hacl(Zone,H,Protocol,Port)"),
    case("direct_network_access", DIRECT, "netAccess(H,Protocol,Port)",
         "attackerLocated(Zone)", "hacl(Zone,H,Protocol,Port)"),
    case("valid_accounts", "Valid Accounts - T1078", "execCode(H,Perm)",
         "attackerLocated(Zone)", "hacl(Zone,H,_,_)", "leakAccount(_,H,Perm)"),
    case("weak_account_initial", BRUTE, "execCode(H,Perm)",
         "attackerLocated(Zone)", "hacl(Zone,H,_,_)", "weakAccount(H,User,Passwd,Perm)"),
    case("public_application_initial", PUBLIC, "execCode(H,Perm)",
         "ttpExists(H,_,Software,remoteExploit,publicApplicationExploit,initialAccess)",
         "networkServiceInfo(H,Software,Protocol,Port,Perm)", "netAccess(H,Protocol,Port)"),
    case("lsass_admin", LSASS, "getAccount(H,User,Passwd,Perm)",
         "ttpExists(H,Software,_,lsassCredentialDumping,credentialAccess)",
         "networkServiceInfo(H,Software,_,_,_)", "hasAccount(H,User,Passwd,Perm)", "execCode(H,admin)"),
    case("lsass_system", LSASS, "getAccount(H,User,Passwd,Perm)",
         "ttpExists(H,Software,_,domainCredentialDumping,credentialAccess)",
         "networkServiceInfo(H,Software,_,_,system)", "hasAccount(H,User,Passwd,Perm)", "execCode(H,system)"),
    case("weak_account_lateral", BRUTE, "execCode(HostD,Perm)",
         "execCode(HostS,_)", "weakAccount(HostD,_,_,Perm)", "hacl(HostS,HostD,Protocol,Port)",
         different=(("Port", "2049"), ("Port", "873"))),
    case("client_execution_internet", "Exploitation for Client Execution internet - T1203", "execCode(H,Perm)",
         "ttpExists(H,_,Software,_,clientVulnerability,execution)",
         "networkServiceInfo(H,Software,Protocol,Port,Perm)", "attackVectorInjection(H,_,Protocol,Port)"),
    case("ddos_exploitation", "DDOS-Application or System Exploitation - T1499.004", "execCode(H,Perm)",
         "ttpExists(H,_,Software,remoteClient,ddosForExploit,impact)",
         "networkServiceInfo(H,Software,Protocol,Port,Perm)", "attackVectorInjection(H,_,Protocol,Port)"),
    case("boundary_bridge_lateral", "Network Boundary Bridging Network Address Translation Traversal - T1599.001", "execCode(HostD,Perm)",
         "execCode(HostS,Perm)", "ttpExists(HostD,_,Software,remoteClient,networkBoundaryBridging,defenseEvasion)",
         "networkServiceInfo(HostD,Software,Protocol,Port,Perm)", "hacl(HostS,HostD,Protocol,Port)"),
    case("masquerading", "Masquerading - Match Legitimate Name or Location - T1036.005", "execCode(HostD,Perm)",
         "hacl(HostS,HostD,Protocol,Port)", "ttpExists(HostD,Software,remoteClient,disguisedLegitimateDocument,defenseEvasion)",
         "networkServiceInfo(HostD,Software,Protocol,Port,Perm)", "netAccess(HostD,Protocol,Port)"),
    case("disable_firewall", "Impair Defenses - Disable or Modify Tools - T1562.001", "disableFirewall(HostD)",
         "isFirewall(HostD,exit)", "execCode(HostS,system)",
         "ttpExists(HostD,Software,remoteClient,remoteDisableDefenses,defenseEvasion)",
         "networkServiceInfo(HostD,Software,Protocol,Port,Perm)", "hacl(HostS,HostD,Protocol,Port)"),
    # AGV D32-h: rules5_v2.P carries the credential pair the T1021 rules already use
    # (getAccount on the source host, hasAccount on the target). The frozen rules5.P shape
    # above stays as it was, so both graphs keep a matching case; only v2 reports accounts.
    case("disable_firewall_credentialed", "Impair Defenses - Disable or Modify Tools - T1562.001", "disableFirewall(HostD)",
         "isFirewall(HostD,exit)", "execCode(HostS,system)",
         "ttpExists(HostD,Software,remoteClient,remoteDisableDefenses,defenseEvasion)",
         "networkServiceInfo(HostD,Software,Protocol,Port,Perm)", "hacl(HostS,HostD,Protocol,Port)",
         "getAccount(HostS,User,Passwd,system)", "hasAccount(HostD,User,Passwd,system)"),
    case("boundary_bridge_injected", "Network Boundary Bridging - Network Address Translation Traversal - T1599.001", "execCode(HostD,Perm)",
         "attackVectorInjection(HostD,_,Protocol,Port)",
         "ttpExists(HostD,_,Software,remoteClient,networkBoundaryBridging,defenseEvasion)",
         "networkServiceInfo(HostD,Software,Protocol,Port,Perm)"),
    case("process_injection", "Process Injection - T1055", "execCode(H,admin)",
         "ttpExists(H,Software,local,processInjection,privilegeEscalation)",
         "networkServiceInfo(H,Software,_,_,admin)", "execCode(H,Perm)",
         different=(("Perm", "admin"), ("Perm", "root"))),
    case("local_privilege_exploit", ESCALATION, "execCode(H,Perm1)",
         "ttpExists(H,_,Software,local,privilegeEscalationExploit,privilegeEscalation)",
         "networkServiceInfo(H,Software,_,_,Perm1)", "execCode(H,Perm)",
         different=(("Perm", "admin"), ("Perm", "root"))),
    case("scheduled_task", "Scheduled Task Job At - T1053.002", "execCode(H,admin)",
         "ttpExists(H,Software,local,scheduledTaskExploit,privilegeEscalation)",
         "networkServiceInfo(H,Software,_,_,admin)", "execCode(H,Perm)",
         different=(("Perm", "admin"), ("Perm", "root"))),
    case("public_application_privilege", PUBLIC, "execCode(H,system)",
         "ttpExists(H,_,Software,local,publicApplicationExploit,privilegeEscalation)",
         "networkServiceInfo(H,Software,_,_,system)", "execCode(H,Perm)", different=(("Perm", "system"),)),
    case("path_hijack_admin", PATH, "execCode(H,admin)",
         "ttpExists(H,Software,local,pathHijack,privilegeEscalation)", "pathExists(H,_,write,admin)", "execCode(H,Perm)",
         different=(("Perm", "admin"), ("Perm", "root"))),
    case("path_hijack_root", PATH, "execCode(H,root)",
         "ttpExists(H,Software,local,pathHijack,privilegeEscalation)", "pathExists(H,_,write,root)", "execCode(H,Perm)",
         different=(("Perm", "admin"), ("Perm", "root"))),
    case("container_escape", ESCALATION, "execCode(H,root)",
         "execCode(Docker,root)", "ttpExists(H,_,local,escapetoHost,privilegeEscalation)", "isDocker(H,Docker)"),
    case("command_interpreter", "Command and Scripting Interpreter - T1623", "execCode(HostD,Perm)",
         "execCode(HostS,_)", "networkServiceInfo(HostD,Software,Protocol,Port,Perm)",
         "ttpExists(HostD,Software,remoteExploit,commandInterpreterExploit,execution)", "hacl(HostS,HostD,Protocol,Port)"),
    case("client_execution_intranet", "Exploitation for Client Execution intranet - T1203", "execCode(HostD,Perm)",
         "execCode(HostS,_)", "networkServiceInfo(HostD,Software,Protocol,Port,Perm)",
         "ttpExists(HostD,_,Software,_,clientVulnerability,execution)", "hacl(HostS,HostD,Protocol,Port)"),
    case("visual_basic_lateral", VB, "execCode(HostD,Perm)",
         "execCode(HostS,_)", "networkServiceInfo(HostD,Software,Protocol,Port,Perm)",
         "ttpExists(HostD,_,Software,_,abuseofVBScriptorVBA,execution)", "hacl(HostS,HostD,Protocol,Port)"),
    case("visual_basic_injected", VB, "execCode(HostD,Perm)",
         "attackVectorInjection(HostD,_,Protocol,Port)", "networkServiceInfo(HostD,Software,Protocol,Port,Perm)",
         "ttpExists(HostD,_,Software,_,abuseofVBScriptorVBA,execution)"),
    case("browser_session", "Browser Session Hijacking - T1185", "execCode(HostD,Perm)",
         "execCode(HostS,_)", "networkServiceInfo(HostD,Software,Protocol,Port,Perm)",
         "ttpExists(HostD,_,Software,_,browserSessionHijacking,collection)", "hacl(HostS,HostD,Protocol,Port)"),
    case("nfs_remote_management", "Remote Services - SMB Windows Admin Shares - T1021.002", "execCode(HOSTD,Perm)",
         "networkServiceInfo(HOSTD,Software,Protocol,Port,Perm)", "nfsMount(HOSTD,_,Software,write,HOSTS)",
         "ttpExists(HOSTD,Software,_,linuxRemoteManagement,lateralMovement)", "execCode(HOSTS,_)", "hacl(HOSTS,HOSTD,Protocol,Port)"),
    case("winrm_system_firewall_state", WINRM, "execCode(HOSTD,Perm)",
         "networkServiceInfo(HOSTD,winrm,Protocol,Port,_)", "hacl(HOSTS,HOSTD,Protocol,Port)",
         "execCode(HOSTS,system)", "isFirewall(HOSTD,flase)", "getAccount(_,User,Passwd,Perm)", "hasAccount(HOSTD,User,Passwd,Perm)"),
    case("winrm_admin_firewall_state", WINRM, "execCode(HOSTD,Perm)",
         "networkServiceInfo(HOSTD,winrm,Protocol,Port,_)", "hacl(HOSTS,HOSTD,Protocol,Port)",
         "execCode(HOSTS,admin)", "isFirewall(HOSTD,flase)", "getAccount(_,User,Passwd,Perm)", "hasAccount(HOSTD,User,Passwd,Perm)"),
    case("winrm_system_after_firewall_disable", WINRM, "execCode(HOSTD,Perm)",
         "networkServiceInfo(HOSTD,winrm,Protocol,Port,_)", "hacl(HOSTS,HOSTD,Protocol,Port)",
         "execCode(HOSTS,system)", "disableFirewall(HOSTD)", "getAccount(_,User,Passwd,Perm)", "hasAccount(HOSTD,User,Passwd,Perm)"),
    case("windows_credential_remote_system_firewall_state", WIN_CRED_REMOTE, "execCode(HOSTD,Perm)",
         "ttpExists(HOSTD,RemoteService,_,windowsCredentialRemoteExecution,lateralMovement)",
         "networkServiceInfo(HOSTD,RemoteService,Protocol,Port,_)", "hacl(HOSTS,HOSTD,Protocol,Port)",
         "execCode(HOSTS,system)", "isFirewall(HOSTD,flase)", "getAccount(_,User,Passwd,Perm)", "hasAccount(HOSTD,User,Passwd,Perm)"),
    case("windows_credential_remote_admin_firewall_state", WIN_CRED_REMOTE, "execCode(HOSTD,Perm)",
         "ttpExists(HOSTD,RemoteService,_,windowsCredentialRemoteExecution,lateralMovement)",
         "networkServiceInfo(HOSTD,RemoteService,Protocol,Port,_)", "hacl(HOSTS,HOSTD,Protocol,Port)",
         "execCode(HOSTS,admin)", "isFirewall(HOSTD,flase)", "getAccount(_,User,Passwd,Perm)", "hasAccount(HOSTD,User,Passwd,Perm)"),
    case("windows_credential_remote_system_after_firewall_disable", WIN_CRED_REMOTE, "execCode(HOSTD,Perm)",
         "ttpExists(HOSTD,RemoteService,_,windowsCredentialRemoteExecution,lateralMovement)",
         "networkServiceInfo(HOSTD,RemoteService,Protocol,Port,_)", "hacl(HOSTS,HOSTD,Protocol,Port)",
         "execCode(HOSTS,system)", "disableFirewall(HOSTD)", "getAccount(_,User,Passwd,Perm)", "hasAccount(HOSTD,User,Passwd,Perm)"),
    case("pass_the_hash", "Use Alternate Authentication Material - Pass the Hash - T1550.002", "execCode(HOSTD,Perm)",
         "networkServiceInfo(HOSTD,smb,Protocol,Port,_)", "hacl(HOSTS,HOSTD,Protocol,Port)",
         "execCode(HOSTS,admin)", "getAccount(_,User,Passwd,_)", "hasAccount(HOSTD,User,Passwd,Perm)"),
    case("rdp_hijack", "Remote Service Session RDP Hijacking - T1563.002", "execCode(HOSTD,Perm)",
         "networkServiceInfo(HOSTD,rds,Protocol,Port,_)", "hacl(HOSTS,HOSTD,Protocol,Port)",
         "execCode(HOSTS,admin)", "getAccount(_,User,Passwd,Perm)", "hasAccount(HOSTD,User,Passwd,Perm)"),
    case("remote_services_without_cve", REMOTE, "execCode(HOSTD,Perm)",
         "ttpExists(HOSTD,Software,_,remoteServicesExploitation,lateralMovement)",
         "networkServiceInfo(HOSTD,Software,Protocol,Port,Perm)", "hacl(HOSTS,HOSTD,Protocol,Port)", "execCode(HOSTS,_)"),
    case("remote_services_with_cve", REMOTE, "execCode(HOSTD,Perm)",
         "ttpExists(HOSTD,_,Software,_,remoteServicesExploitation,lateralMovement)",
         "networkServiceInfo(HOSTD,Software,Protocol,Port,Perm)", "hacl(HOSTS,HOSTD,Protocol,Port)", "execCode(HOSTS,_)"),
    case("ssh_hijack", "Remote Service Session SSH Hijacking - T1563.001", "execCode(HostD,Perm)",
         "execCode(HostS,_)", "networkServiceInfo(HostD,Software,Protocol,Port,Perm)",
         "ttpExists(HostD,Software,remoteExploit,sshHijacking,lateralMovement)", "hacl(HostS,HostD,Protocol,Port)"),
)

# Pre-parse once, rather than reparsing all templates for each graph node.
PATTERNS = {
    item.id: (parse_fact(item.head), tuple(map(parse_fact, item.body)))
    for item in CASES
}
