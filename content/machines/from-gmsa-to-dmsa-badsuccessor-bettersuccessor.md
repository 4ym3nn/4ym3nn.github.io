+++
date = '2026-10-10T12:00:00+01:00'
draft = true
title = 'From gMSA to dMSA: Understanding BadSuccessor and BetterSuccessor'
description = 'A technical deep dive into Active Directory managed service accounts, dMSA migration, Kerberos authentication, and the BadSuccessor and BetterSuccessor privilege escalation techniques.'
hideToc = false
tags = ['Active Directory', 'Windows Server 2025', 'Kerberos', 'gMSA', 'dMSA', 'BadSuccessor', 'BetterSuccessor', 'Privilege Escalation', 'Security Research']
+++

# From gMSA to dMSA: Understanding BadSuccessor and BetterSuccessor

When I first started reading about BadSuccessor, I got stuck on a basic question: what exactly is a managed service account? Is it a user, a computer, or simply a username and password that a service uses?

That question turned out to be the right place to start. The interesting part of BadSuccessor is not a complicated Kerberos command. It is what happens when Active Directory allows one account to succeed another, and the Key Distribution Center (KDC) decides which privileges should follow that relationship.

This article works through the foundations first, then the original BadSuccessor vulnerability, Microsoft's patch, and the post-patch technique known as BetterSuccessor. It is an explanation of published research, not a claim of a new discovery. The main sources are Microsoft's documentation, [Yuval Gordon's original Akamai research](https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory), [Akamai's patch analysis](https://www.akamai.com/blog/security-research/badsuccessor-is-dead-analyzing-badsuccessor-patch), and [Shaunak Khosla's BetterSuccessor article](https://www.alteredsecurity.com/post/bettersuccessor-still-abusing-dmsa-for-privilege-escalation-badsuccessor-after-patch).

## 1. Why Do Service Accounts Exist?

Imagine a company running Microsoft SQL Server on a machine called `SQL01`. The database service needs to keep running when nobody is logged in. It may also need to write backups to a remote file share.

Windows needs to know **which security identity** the service is using. One option is a normal domain user account created for that purpose:

```text
SQL Server service on SQL01
          |
          v
    CORP\svc_sql
          |
          v
  \\FILE01\Backups
```

**Figure 1.** A Windows service running under a dedicated domain identity.

The account `CORP\svc_sql` has its own security identifier (SID), credentials, and permissions. It is not a person, even though it may be represented by an ordinary AD user object. It is an identity used by software.

Not every Windows service needs a dedicated domain account. Built-in identities such as `LocalSystem` and `NetworkService`, along with virtual service accounts, are also options. Which one is appropriate depends on what the service must access.

### The problem with a traditional domain account

Suppose an administrator sets a password for `svc_sql`, configures the service, and moves on. Months later, that password needs to change. If the same account is used by several applications, every dependent service must be updated correctly or something may stop working.

That creates an unpleasant incentive to leave service passwords unchanged for long periods. A forgotten service identity may also accumulate permissions far beyond what it originally needed.

There is a Kerberos angle as well. If an account has a Service Principal Name (SPN), an authenticated domain user can often request a service ticket for it. Part of that ticket can be used for offline password guessing, which is the basis of **Kerberoasting**. Weak, human-chosen service passwords make this much more practical.

Microsoft's managed service accounts were designed to reduce this operational burden by letting Windows and Active Directory handle service credentials.

## 2. sMSA and gMSA: An Identity, Not a Computer

Before comparing the account types, one distinction matters:

| Example | What it represents |
| --- | --- |
| `CORP\alice` | A human user's AD identity |
| `CORP\WEB01$` | A domain-joined computer's identity |
| `CORP\webapp$` | A managed service identity used by an application |

The trailing `$` is common for computer and managed service accounts, but it does not mean they are the same thing. A managed service account has its own AD identity. It is not merely a password stored on `WEB01`, and creating one does not create a new physical or virtual server.

### Standalone Managed Service Accounts (sMSA)

Introduced with Windows Server 2008 R2, an **sMSA** provides automatic password management and simpler SPN management for services on a **single computer**.

For example, a service on `WEB01` could run as `CORP\svc_web$`. Windows manages the credential lifecycle instead of requiring an administrator to type in a long-lived password.

The limitation is the single-host design. If the same application runs on several servers behind a load balancer, an sMSA cannot serve as the shared identity for all of them.

### Group Managed Service Accounts (gMSA)

Windows Server 2012 introduced **gMSAs** to solve that problem.

Suppose `WEB01`, `WEB02`, and `WEB03` run different instances of the same application. They can all use `CORP\webapp$` as the service identity, provided their computer accounts are authorized to retrieve its managed password.

```text
 WEB01$       WEB02$       WEB03$
    \            |            /
     \           |           /
      Authorized to retrieve
         managed credentials
                 |
                 v
          CORP\webapp$
              (gMSA)
```

**Figure 2.** Multiple authorized computers using one gMSA identity.

Active Directory uses the **Key Distribution Service (KDS)** and its root key material to support managed password generation. Domain controllers derive the gMSA password, and authorized hosts can obtain the current and preceding password values. By default, gMSA passwords rotate every **30 days**. [Microsoft documents this behavior here](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-service-accounts).

The authorized principals are configured through `PrincipalsAllowedToRetrieveManagedPassword`. In the directory, the corresponding access-control information is represented by `msDS-GroupMSAMembership`.

One point is easy to mix up: **KDS and KDC are different components**. KDS helps with managed key generation; the Kerberos KDC authenticates principals and issues tickets.

A gMSA reduces weak-password and password-rotation problems. It does not make credential theft impossible. A sufficiently privileged attacker on an authorized host may still be able to obtain credential material available to that machine.

## 3. What Makes dMSA Different?

Windows Server 2025 introduced **delegated Managed Service Accounts (dMSAs)**. They are also AD service identities, but their design is more closely bound to the identity of the authorized machine.

With a gMSA, a permitted host retrieves a managed password. With a dMSA, the domain controller keeps the randomized secret and uses a device-linked Kerberos authentication mechanism to supply the necessary authentication material. Credential Guard can provide additional protection. [Microsoft's dMSA overview](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/delegated-managed-service-accounts/delegated-managed-service-accounts-overview) describes this model.

In simpler terms:

- **gMSA:** Several authorized computers can run a service under one shared managed identity.
- **dMSA:** A service identity is tied more tightly to authorized device authentication, rather than ordinary retrieval of a reusable gMSA password.

A dMSA is still **not** the computer account itself. If `WEB01$` uses `backup_dmsa$`, those are separate security principals. The machine's identity helps authorize use of the service identity.

There is another important feature: a dMSA can replace a traditional service account while preserving the access that the old service needs. It can also exist as a standalone dMSA without migrating another account.

This migration feature is where BadSuccessor begins. Microsoft's documented migration flow supports traditional service accounts, not direct migration from an existing sMSA or gMSA.

## 4. How dMSA Migration Works

Imagine a company has used `CORP\svc_backup` for years. The account already has access to a file server, a backup location, and several scheduled jobs.

The administrators want to move that service to `CORP\backup_dmsa$` without manually rebuilding every permission.

In a legitimate migration, `svc_backup` becomes the **predecessor**, also called the **superseded account**. The new dMSA becomes its successor.

### Two stages, not one

Microsoft provides two cmdlets for the transition:

1. `Start-ADServiceAccountMigration` begins migration. The service continues using its old identity while compatible hosts are discovered and authorized to use the new dMSA.
2. `Complete-ADServiceAccountMigration` completes the transition. Supported settings such as SPNs are transferred, and the old account is disabled.

Administrators must plan for compatible client machines, ticket lifetimes, and AD replication. This is intended to be a controlled migration, not an arbitrary edit to one directory object.

### The attributes behind the relationship

Akamai's research and the Windows Server 2025 schema identify four especially relevant attributes:

| Attribute | Object | Meaning |
| --- | --- | --- |
| `msDS-ManagedAccountPrecededByLink` | dMSA | Identifies the original account |
| `msDS-DelegatedMSAState` | dMSA | Records the dMSA migration state |
| `msDS-SupersededManagedAccountLink` | Original account | References the successor dMSA |
| `msDS-SupersededServiceAccountState` | Original account | Records the original account's migration state |

The state value `1` indicates migration in progress, while `2` indicates completed migration. Akamai also observed `3` for a standalone dMSA; that value comes from its behavioral research rather than the migration-state table in Microsoft's overview.

The relationship is supposed to be mutual:

```text
Original account: svc_backup
  msDS-SupersededManagedAccountLink --> backup_dmsa$
  msDS-SupersededServiceAccountState = 2

New account: backup_dmsa$
  msDS-ManagedAccountPrecededByLink --> svc_backup
  msDS-DelegatedMSAState = 2
```

**Figure 3.** The two sides of a completed migration relationship.

The dMSA's `msDS-GroupMSAMembership` also controls which machine principals are authorized to use it.

A small documentation detail is worth noting: Microsoft's dMSA overview uses inconsistent spellings for two predecessor-side attributes in its migration steps. The names in the table above match the published Windows Server 2025 AD schema and the researchers' analyses.

## 5. Why Kerberos and the PAC Matter

At this point, we have a new service identity and a link to the old one. But how does the new account actually retain access?

A quick Kerberos refresher helps:

```text
Client            Domain Controller / KDC           Service
  |                       |                            |
  |--- AS-REQ ----------->|                            |
  |<-- AS-REP + TGT ------|                            |
  |                       |                            |
  |--- TGS-REQ + TGT ---->|                            |
  |<-- TGS-REP + ticket --|                            |
  |                                                    |
  |------------ Service ticket ----------------------->|
```

**Figure 4.** Simplified Kerberos ticket flow.

The **Ticket-Granting Ticket (TGT)** lets a client request tickets for specific services. It is not a universal access pass. A service still has to evaluate whether the authenticated identity is permitted to perform the requested action.

Windows Kerberos tickets usually contain a **Privilege Attribute Certificate (PAC)**. The PAC carries authorization-related information, including account and group SIDs. Those identifiers help Windows evaluate access against security descriptors and ACLs.

Akamai observed an important detail in dMSA migration: the dMSA's PAC could contain not only its own SID, but also the SIDs and group memberships of the account it replaced. This is how the successor can preserve the predecessor's effective access without literally copying every group membership into the dMSA object's `memberOf` attribute.

### The key package is a separate mechanism

The **PAC** is about authorization. The **`KERB-DMSA-KEY-PACKAGE`** is about cryptographic key material. These must not be confused.

Microsoft's [MS-KILE specification](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/87f5f362-e53c-4949-9a6c-bc9184054517) defines `current-keys` and optional `previous-keys` fields. It also documents that the package can include keys associated with both the dMSA and the legacy account involved in migration.

Akamai found that this mechanism had a second security implication. An abused predecessor link could expose the target account's Kerberos key material, not just its authorization information. That matters because a reusable key can potentially be used to authenticate as the original account.

So the original attack had **two important consequences**: privilege inheritance through the PAC and possible predecessor credential exposure through the key package.

## 6. BadSuccessor: The Original Vulnerability

In May 2025, Akamai researcher **Yuval Gordon** published [BadSuccessor](https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory). The vulnerability affected the dMSA functionality on vulnerable Windows Server 2025 domain controllers.

What made it serious was the starting permission. The attacker did not need to control the target account.

### From `CreateChild` to a false successor

Suppose a low-privileged user has permission to create dMSA objects inside `OU=Development`. That can come from the specific `CreateChild` permission for the dMSA class or a broader permission to create child objects.

The user can create a new dMSA there and, if they control its attributes, configure a relationship like this:

```text
attacker_dmsa$
  msDS-ManagedAccountPrecededByLink = Administrator
  msDS-DelegatedMSAState = 2
```

This is **not** a legitimate migration. It is a claim, made entirely on an account the attacker controls, that Administrator has been superseded.

The security mistake was in the vulnerable KDC's interpretation of that claim. The KDC could accept the one-sided relationship when constructing the dMSA's authorization data and supplying associated key material.

As a result, the dMSA could receive Administrator-related SIDs and group memberships in its PAC, even though the attacker had never modified Administrator and did not know Administrator's password. Akamai also demonstrated the associated credential-exposure behavior.

### Where the trust boundary failed

I think this is the easiest way to understand the root cause:

**Permission to create a new service account is not permission to inherit the privileges of any other account in the domain.**

Active Directory might correctly allow an attacker to create a child object in a delegated OU. That decision does not authorize a migration from a completely unrelated Tier 0 account. The vulnerable KDC blurred those two decisions.

This is why describing BadSuccessor as simply a missing ACL check is incomplete. The more precise issue was **insufficient validation of a security-sensitive account-succession relationship**.

One more practical lesson: seeing `TGT request successful` proves that a Kerberos authentication exchange succeeded. It does **not** prove that Administrator's authorization data is present or that an administrative operation will succeed. The PAC and the target service's access checks matter.

## 7. Microsoft's August 2025 Patch

Microsoft fixed the original BadSuccessor vulnerability, tracked as **CVE-2025-53779**, in the security updates released on **August 12, 2025**. The [NVD entry](https://nvd.nist.gov/vuln/detail/CVE-2025-53779) identifies the affected Windows Server 2025 versions and the relevant fixed-build boundary.

Akamai published a [follow-up analysis on August 27, 2025](https://www.akamai.com/blog/security-research/badsuccessor-is-dead-analyzing-badsuccessor-patch) explaining what changed.

The fix was more interesting than simply making one LDAP attribute read-only.

### The KDC checks both sides

Before the patch, a dMSA-side predecessor link could be enough. After the patch, Akamai observed that the KDC requires the relationship to be **mutual** and checks the original account's successor information as well.

```text
Before the patch:
  attacker_dmsa$ ---> Administrator
  Administrator   -X-> attacker_dmsa$
  One-sided claim could be accepted.

After the patch:
  attacker_dmsa$ ---> Administrator
  Administrator   ---> attacker_dmsa$
  KDC requires a consistent relationship.
```

**Figure 5.** The central change introduced by the patch.

The KDC's updated validation was observed in `kdcsvc.dll`. Writing the dMSA's predecessor link could still succeed, but the KDC would no longer honor the false migration if the target account did not contain the corresponding relationship.

Akamai also observed that a relationship could still work with an **enabled** predecessor account, even though the standard completed migration normally disables that account. The patch therefore strengthened ticket-time validation without making every malformed or maliciously configured migration impossible.

The key security result is straightforward: **control of only the dMSA no longer provides the original arbitrary-target escalation path on a patched KDC**.

## 8. BetterSuccessor: What's Actually New?

This is where I initially had doubts about the terminology. If Microsoft's patch requires the attacker to modify the target account too, then haven't we already crossed a serious permission boundary?

Yes. That is exactly why **BetterSuccessor should be described as a post-patch attack technique, not a new equivalent of the original BadSuccessor vulnerability**.

In November 2025, **Shaunak Khosla** of Altered Security published [BetterSuccessor](https://www.alteredsecurity.com/post/bettersuccessor-still-abusing-dmsa-for-privilege-escalation-badsuccessor-after-patch), demonstrating how the dMSA migration mechanism could still be abused on patched domain controllers by a better-positioned attacker.

### The stronger prerequisites

The attacker now needs two relevant capabilities:

1. Control of a dMSA, for example by creating one in an OU where dMSA creation is permitted.
2. Sufficient write access to the target account's migration-related attributes, such as access available through a dangerous `GenericWrite` permission.

With that control, the attacker can establish the mutual predecessor-successor relationship that the patched KDC expects. The KDC may then recognize the migration, allowing the dMSA to operate with the predecessor's effective authorization information and, through the dMSA key package, potentially obtain the predecessor's key material.

This does **not** mean that `GenericWrite` on a privileged user was harmless before BetterSuccessor. Far from it. Such permissions can already support other account-takeover techniques, depending on the target and its protections.

### Why does BetterSuccessor still matter?

Because it gives an attacker a **different primitive** for turning existing AD object control into account compromise.

Akamai describes post-patch dMSA abuse as a possible alternative to shadow credentials for targeted credential and privilege acquisition. It can also offer a targeted, replication-free route to retrieve keys in an already-compromised domain, rather than relying on the DCSync replication interface.

That matters operationally. The attacker may act through the dMSA identity, and the detection trail can differ from that of shadow credentials or DCSync. But it is not invisible. Directory modifications, unusual dMSA authentication, and access attempts still provide defenders with opportunities to detect abuse.

Here is the comparison I find most useful:

| Question | Original BadSuccessor | BetterSuccessor |
| --- | --- | --- |
| KDC state | Vulnerable, pre-August 2025 patch | Patched KDC with mutual validation |
| Control over dMSA | Required | Required |
| Write access to target object | Not required | Required |
| Relationship | One-sided false predecessor claim | Mutual pairing established by attacker |
| Main significance | New low-privilege escalation path | Alternative abuse path for an already dangerous ACL position |

I would not call BetterSuccessor a bypass that restores the original vulnerability. **It works by satisfying the KDC's stronger relationship checks after obtaining additional control over the target.**

At the time of writing, I did not find a separately documented Microsoft CVE or security update specifically addressing BetterSuccessor. That is not proof that every newer build behaves identically; behavior should be validated against the actual patch level and environment.

## 9. Detection and Hardening

The defense is not just to install one security update and forget about dMSAs. The August 2025 fix closes the original one-sided escalation, but excessive permissions over service-account and target-account objects still matter.

These are the controls I would prioritize:

1. **Patch all relevant Windows Server 2025 domain controllers.** The original BadSuccessor attack depends on vulnerable KDC behavior.
2. **Review OU-level `CreateChild` permissions.** Delegated object creation should not silently include the ability to create sensitive service-account classes unless that access is necessary.
3. **Remove unnecessary write permissions on sensitive accounts.** In particular, look for broad rights such as `GenericWrite`, `GenericAll`, and `WriteDacl` over Tier 0 users and computers.
4. **Protect both sides of a dMSA migration.** Audit who can create and configure the dMSA, change its authorized machines, and edit the predecessor account's successor relationship.
5. **Monitor directory and Kerberos activity together.** With the appropriate audit policies and SACLs, Event ID `5137` can help identify AD object creation and `5136` can identify attribute modifications. Kerberos events `4768` and `4769` can provide additional authentication context.

Attributes worth watching include:

```text
msDS-GroupMSAMembership
msDS-ManagedAccountPrecededByLink
msDS-DelegatedMSAState
msDS-SupersededManagedAccountLink
msDS-SupersededServiceAccountState
```

A particularly suspicious pattern would be a newly created dMSA followed by migration-link changes on a high-privilege account that was never scheduled for service-account migration.

Be careful with auditing assumptions. Windows does not automatically generate detailed change events for every object and attribute. [Microsoft's auditing guidance](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-directory-service-changes) explains that suitable SACLs and directory service auditing must be configured first.

## 10. Final Thoughts

My biggest takeaway from researching BadSuccessor is how much damage can come from trusting the wrong relationship between two otherwise ordinary AD objects.

Service accounts are not just usernames and passwords. They are security identities. gMSAs improve how those identities receive managed credentials. dMSAs go further by linking authentication to authorized devices and providing a migration path for older service identities.

That migration path creates a necessary trust decision: **which old account is this dMSA genuinely allowed to replace?**

The original BadSuccessor vulnerability showed what happens when the KDC accepts an unsupported answer to that question. Microsoft's August 2025 patch closed that route by validating both sides of the relationship. BetterSuccessor showed that the same mechanism can still be abused when an attacker already has sufficient control to modify both sides.

For me, the distinction between the two is the most important point in this story. **BadSuccessor exposed a broken authorization boundary. BetterSuccessor demonstrates why dangerous ACLs remain dangerous even after that boundary has been strengthened.**

Understanding the difference is more useful than memorizing an exploit command.

## References

The primary sources used for this article are:

1. **Microsoft Learn**, [Service accounts in Windows Server](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-service-accounts). Overview of traditional accounts, sMSAs, gMSAs, and dMSAs.
2. **Microsoft Learn**, [Group Managed Service Accounts overview](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/group-managed-service-accounts/group-managed-service-accounts/group-managed-service-accounts-overview). gMSA design and password management.
3. **Microsoft Learn**, [Delegated Managed Service Accounts overview](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/delegated-managed-service-accounts/delegated-managed-service-accounts-overview). dMSA authentication and migration.
4. **Microsoft Open Specifications**, [KERB-DMSA-KEY-PACKAGE (MS-KILE)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/87f5f362-e53c-4949-9a6c-bc9184054517). Current and previous Kerberos keys.
5. **Microsoft Open Specifications**, [Privilege Attribute Certificate (MS-PAC)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/166d8064-c863-41e1-9c23-edaaa5f36962). PAC authorization data.
6. **Yuval Gordon, Akamai, May 21, 2025**, [BadSuccessor: Abusing dMSA to Escalate Privileges in Active Directory](https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory). Original discovery and technical analysis.
7. **Yuval Gordon, Akamai, August 27, 2025**, [BadSuccessor Is Dead, Long Live BadSuccessor(?)](https://www.akamai.com/blog/security-research/badsuccessor-is-dead-analyzing-badsuccessor-patch). Patch analysis and remaining attack primitives.
8. **Shaunak Khosla, Altered Security, November 18, 2025**, [BetterSuccessor: Still Abusing dMSA for Privilege Escalation](https://www.alteredsecurity.com/post/bettersuccessor-still-abusing-dmsa-for-privilege-escalation-badsuccessor-after-patch). Post-patch research, subsequently updated in February 2026.
9. **Microsoft Open Specifications**, [msDS-SupersededManagedAccountLink](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-ada2/c5b9ddb6-a9dd-4bdc-9a68-775fb346f21e) and [msDS-SupersededServiceAccountState](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-ada2/188941fa-3e05-4d4e-89e7-bb70ad67a737). Schema-verified LDAP attribute names.
10. **NIST National Vulnerability Database**, [CVE-2025-53779](https://nvd.nist.gov/vuln/detail/CVE-2025-53779). Affected Windows Server 2025 versions and advisory references.
11. **Microsoft Learn**, [Audit Directory Service Changes](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-directory-service-changes). Directory modification and creation events, and the SACL requirement.
