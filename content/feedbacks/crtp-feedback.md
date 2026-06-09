+++
date = '2026-06-09T17:40:00+01:00'
draft = false
title = 'Certified Red Team Professional (CRTP) - Review & Feedback'
hideToc = false
tags = ['Active Directory', 'Red Teaming', 'CRTP', 'Review', 'Certification']
+++

# Certified Red Team Professional (CRTP) Review & Feedback

I won the CRTP certificate voucher in the **WorldWideCTF** competition with my team **TroJeun**. Since no one else on the team was interested in it, I decided to take it—and it was the best decision I've made, as it introduced me to the massive world of Red Teaming! A huge thanks to my teammates and the WorldWideCTF staff for this amazing prize.

![Certified Red Team Professional (CRTP)](/images/crtp-certificate.png)

---

## Context

Getting introduced to Active Directory security and enterprise exploitation was something I always wanted to do, but I wasn't sure where to start. Winning the CRTP voucher at WorldWideCTF with my team **TroJeun** was the perfect catalyst. Taking on this challenge turned out to be a game-changer, sparking a deep interest in low-level systems, Active Directory attack vectors, and red team methodologies.

---

## Bootcamp

The CRTP bootcamp (Attacking and Defending Active Directory) by Altered Security is a fully hands-on course. It provides:
- High-quality video lectures and a comprehensive PDF workbook.
- A student VM with a low-privileged domain user.
- A fully patched Active Directory lab representing a realistic enterprise infrastructure (multiple domains, forests, trust relationships, SQL servers, and AD CS).

The labs are exceptionally stable and guide you step-by-step through:
1. Local privilege escalation and defense bypasses.
2. Active Directory enumeration (using PowerView and BloodHound).
3. Lateral movement and domain privilege escalation (Kerberoasting, Constrained/Unconstrained Delegation, RBCD).
4. Domain persistence (Golden/Silver/Diamond tickets, Skeleton Key, DCSync, AdminSDHolder).
5. Forest trust abuse.

---

## Exam (CRTP)

The CRTP exam is a **24-hour practical challenge** followed by another **24 hours for report writing**.
- **The Lab**: You start from a student VM and must compromise a completely patched network.
- **The Goal**: Gain local administrator access on **5 target machines** (including Domain Controllers) in the environment.
- **The Experience**: It is a test of methodology rather than looking for obscure exploits. You abuse native Active Directory features, misconfigurations, and trust relationships to escalate privileges. Standard tools like PowerShell, PowerView, Rubeus, and Mimikatz are key.

---

## Is it worth it?

**Absolutely.**
If you want to transition from standard network pentesting to Active Directory exploitation and Red Teaming, the CRTP is the best entry-point. Unlike other certifications that rely on outdated kernel exploits, CRTP forces you to understand AD architecture, authentication protocols (Kerberos, NTLM), and misconfigurations.
- **Difficulty**: 5/10 (Beginner-friendly but requires solid methodology)
- **Quality**: 10/10
- **Overall Rating**: ⭐⭐⭐⭐⭐ (5/5)

---

## Notes

During my preparation, I took extensive notes summarizing the course concepts, Active Directory architecture, and attack vectors. You can read my full course summary here:
👉 **[CRTP Course Summary Notes](/feedbacks/crtp-summary/)**

---

## Tips

Having a reliable cheat sheet is crucial for the 24-hour exam. I compiled all the essential PowerView, Rubeus, and Mimikatz commands used throughout the course:
👉 **[CRTP Practical Exam Cheatsheet](/feedbacks/crtp-cheatsheet/)**

Here are some additional tips for the exam:
- **Enumerate thoroughly**: Do not rush. Spend time understanding the active directory structure.
- **Take screenshots as you go**: Your exam report must document every command and flag capture step-by-step.
- **BloodHound**: Use BloodHound to visualize attack paths, but make sure you also understand how to do the same queries manually using PowerView.
