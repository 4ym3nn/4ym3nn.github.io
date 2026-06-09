+++
date = '2026-06-09T17:30:00+01:00'
draft = true
title = 'Certified Red Team Professional (CRTP) - Review & Feedback'
hideToc = false
tags = ['Active Directory', 'Red Teaming', 'CRTP', 'Review', 'Certification']
+++

# Certified Red Team Professional (CRTP) Review & Feedback

Welcome to my review of the **Certified Red Team Professional (CRTP)** course and exam by Altered Security. If you are looking to dive deep into Active Directory (AD) security and red teaming, this certification is one of the most highly recommended entry-points.

Here is my honest feedback on the course content, lab environment, exam, and some tips to help you pass.

---

## 1. Course Overview & Content

The CRTP course (Attacking and Defending Active Directory) covers the fundamentals of Active Directory security from both an offensive and defensive perspective.

Key topics covered:
- **AD Enumeration**: Querying AD using PowerView, ActiveDirectory PowerShell module, and BloodHound.
- **Local Privilege Escalation**: Bypassing UAC, abusing misconfigured services, and extracting credentials.
- **Domain Privilege Escalation**: Kerberoasting, AS-REP Roasting, abusing ACLs/ACEs, and delegation attacks (constrained, unconstrained, resource-based).
- **Domain Persistence**: Golden/Silver tickets, Skeleton key, DCShadow, ACL modifications, and custom SSPs.
- **Domain Trust Attacks**: Abusing trust relationships (child-to-parent trusts, external trusts, forest trusts).
- **Defense & Detection**: Configuring logging, auditing, and detecting common AD attacks.

---

## 2. The Lab Experience

The lab is a shared environment where you are given a low-privilege domain user on a student VM. 

- **Pros**: The labs are incredibly well-structured. Each video and PDF chapter has corresponding lab exercises that guide you step-by-step.
- **Cons**: Since the lab is shared, you might occasionally see other students' files or changes, but it's generally very stable and resets frequently.

---

## 3. The Exam

The CRTP exam is a **24-hour practical exam** followed by **24 hours for report writing**.

- **Objective**: Gain local administrator access on 5 target machines across the environment (or execute specific red team objectives).
- **Format**: You start with low-privilege access on a student machine and must enumerate, escalate, and move laterally.
- **Tools**: You are expected to use PowerShell (PowerView, PowerUp, Mimikatz) and command-line tools. You do not need complex C2 frameworks; standard PowerShell commands are sufficient.

---

## 4. Tips for Success

- **Understand PowerView/PowerShell**: Knowing how to query AD without GUI tools is essential.
- **Take Detailed Notes**: Make sure you have cheat sheets for every attack type (commands, prerequisites, detection).
- **Do the Labs Multiple Times**: Ensure you can execute every single lab task without looking at the solutions.
- **BloodHound is your friend**: Run BloodHound early during the exam to map out potential attack paths.
- **Focus on the Report**: Take screenshots of every step, command, and output. Your report needs to prove exactly how you compromised each host.

---

## 5. Conclusion

- **Difficulty**: 5/10 (Great for beginners in AD)
- **Value**: 10/10
- **Overall Rating**: ⭐⭐⭐⭐⭐ (5/5)

If you are looking to break into active directory pentesting or red teaming, CRTP is an absolute must-have.
