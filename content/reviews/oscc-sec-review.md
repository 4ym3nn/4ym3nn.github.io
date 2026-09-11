+++
date = '2026-09-11T12:00:00+01:00'
draft = false
title = 'My OSCC-SEC Experience: How I Prepared for Attack, Defend, and Build'
description = 'My honest OSCC-SEC review: how I prepared for Attack, Defend, and Build, what I overthought, and how the six-hour exam went.'
hideToc = false
tags = ['OSCC', 'SEC-100', 'OffSec', 'CyberCore', 'Certification', 'Review']
+++

# My OSCC-SEC Experience

*How I prepared for Attack, Defend, and Build, what I overthought, and how the exam actually felt for me.*

On September 10, 2026, I earned the OffSec CyberCore Certified (OSCC-SEC) certification. I finished the exam with 90 out of 90 points in 1 hour and 57 minutes, but the score is only the last part of the story. Most of the interesting part happened before the exam, while I was trying to decide whether I was actually ready.

I will talk about the public Attack, Defend, and Build structure and how I prepared for it, but not about any exact exam question, vulnerability, machine, remediation task, or answer.

## How I Got Here

I did not originally buy CyberCore as part of a long certification plan. I got the opportunity to take it after winning it through a CTF with my team, Trojeun.

That matters because OSCC was not something I had been preparing toward for years. The opportunity appeared, I already had a lot of offensive practice, and I had to work out what parts of SEC-100 were new to me and what parts I could move through faster.

Before starting this, I had completed the HTB Web Penetration Tester path and most of the HTB CPTS path by myself. I had also spent a lot of time solving HTB machines. Web exploitation, Linux and Windows privilege escalation, Active Directory basics and attacks, enumeration, shells, pivoting, and networking were already familiar. Offensive security was easily my strongest area.

I also completed the SEC-100 course. By the time I was thinking seriously about the exam, my question was not whether I understood basic pentesting. It was whether I could handle the combination of Attack, Defend, and Build, especially the last two.

## What OSCC Actually Tests

The OSCC-SEC exam has three sections: Attack, Defend, and Build. Each section is worth 30 points, for a maximum of 90, and the full proctored exam lasts six hours. OffSec describes each scenario as taking roughly two hours, although candidates can manage their time as they want. The official [OSCC-SEC exam guide](https://help.offsec.com/hc/en-us/articles/27296764876052-OSCC-SEC-Exam-Guide) has the current public structure and rules.

I think the three-part format is the main reason the certification is interesting. It is not a deep offensive exam in the way somebody might expect from OSCP or CPTS. It asks you to switch perspective. One moment you are approaching a system as an attacker, then you need to investigate and repair, then you need to reason about why code or configuration is unsafe.

SEC-100 is broad for the same reason. Some modules were very relevant to my preparation, while I mostly skimmed others. With my background, the offensive content felt foundational. The parts I cared about most were SOC and log analysis, incident response, remediation, secure coding, cloud, input validation, and firewalling.

For someone starting in cybersecurity, that breadth can give useful structure. For someone already deep into CPTS or OSCP-level offensive material, I would treat OSCC more as broad validation than as a deep offensive challenge.

## Was I Ready?

I was not completely sure.

I had done plenty of offensive training, but I did not want to tell myself that completing HTB paths automatically meant I would pass an OffSec exam. So I tested myself on fresh HTB machines, without following a walkthrough.

At one point I got stuck on an Easy machine called Reset. That was enough to make me question my readiness more than it probably should have. Later, I solved BoardLight in about one hour, and that made me much more comfortable with the Attack side.

The useful conclusion was simple: one machine going badly does not necessarily mean I am not ready. A box can expose a gap, or I can miss one detail and lose time. That is different from having no methodology.

I also realized I was spending too much energy thinking about Attack. My offensive background already went beyond most of the SEC-100 offensive depth. More random boxes would always make me a little better, but they were not the best use of my remaining preparation time. My actual gaps were in Defend and Build, so I shifted toward them.

## How I Prepared

I did not try to memorize every command. I wanted a small set of mental loops that I could run under time pressure, with exact syntax kept in searchable notes.

For Attack, my loop was:

> enumerate, hypothesize, validate, gain access, re-enumerate, privilege escalate, get proof

For Defend, I wanted to answer:

> What happened? When? Which host? Which user? Which source? What happened next? What were the initial access, persistence, scope, and root cause? How do I contain it, eradicate it, remediate it, recover, and verify the fix?

For Build, I used:

> What is attacker controlled? Where does it flow? What consumes it? Why is it unsafe? What is the root cause? What is the smallest correct fix? Does legitimate functionality still work?

Those questions were easier to remember than a huge collection of isolated facts. If I needed a command or an exact option, that belonged in my cheat sheets.

### Attack

My Attack preparation was mostly about confirming that my existing process still worked on unfamiliar targets. I was already comfortable enumerating services, forming hypotheses, getting shells, re-enumerating after access, and checking Linux or Windows privilege escalation paths.

The HTB Web Penetration Tester path, most of CPTS, and the time I had spent on machines mattered much more here than last-minute memorization. Solving BoardLight in about an hour was a better readiness signal than rereading another module. At the same time, getting stuck on Reset reminded me not to interpret every bad session as a verdict on my overall skill.

Once I saw that clearly, I stopped making Attack the center of my plan.

### Defend

Defend was where I put the most deliberate work.

Initially, I was confident that I could identify common attacks. My bigger concern was: if I identify the attack, do I actually know how to fix the vulnerable machine correctly?

Finding a suspicious event is one skill. Repairing the system without hiding the symptom or breaking the service is another. I practiced scenario families around SSH password spraying and compromised credentials, SQL injection, malicious file upload and web shells, command injection, exposed vulnerable services, firewall mistakes, weak filesystem permissions, scheduled task or cron persistence, stolen credentials, broken authorization, malware, and cloud secret exposure involving S3 or IAM.

The distinction I repeated until it became automatic was that containment is not remediation.

Blocking an attacker IP is containment. Deleting malware is eradication. Removing a malicious cron job removes persistence. Patching or reconfiguring the vulnerable service addresses the root cause. Replaying the original attack, safely, helps verify that the remediation really worked.

Those actions can all be necessary, but they do not mean the same thing. If I only block one IP while the vulnerable service remains exposed, another source can repeat the attack. If I only delete a web shell while the upload flaw still exists, I have cleaned one artifact and left the door open.

I also practiced preserving legitimate functionality. If SSH is required remotely, blocking port 22 completely is not a correct permanent fix. If users need to upload files, disabling every upload is not a good solution. If a search page has SQL injection, breaking the search page may stop the attack, but it also destroys the feature.

The fix has to remove the unsafe behavior while keeping what the system is supposed to do. That sounds obvious when written in one sentence. In a timed situation, it is easy to reach for the quickest deny rule or delete the visible artifact and feel finished. My Defend preparation was mainly about avoiding that mistake.

### Firewalling

I spent time making `iptables` logic automatic instead of treating each rule like something to decode from scratch.

`INPUT` is traffic going to the host, `OUTPUT` is traffic leaving it, and `FORWARD` is traffic passing through it. The `-i` option refers to the incoming interface and `-o` to the outgoing interface. Rules are evaluated from top to bottom. An `ACCEPT` rule does not magically deny everyone else, because unmatched traffic follows the chain's default policy. Specific allow rules normally need to appear before broader deny rules.

Once those ideas clicked, Module 13 felt extremely easy to me. Before that, firewall questions could look like a wall of flags. Afterward, I was just tracing direction, interface, order, and default behavior.

### Cloud

Cloud was another area I wanted to understand properly instead of memorizing a list of AWS products.

I focused on EC2, S3, IAM, regions, the shared responsibility model, public versus private exposure, temporary versus long-lived credentials, least privilege, ScoutSuite, the AWS CLI, `aws sts get-caller-identity`, EC2 User Data, exposed secrets, and public S3 buckets.

The attack model I kept in my head was familiar:

> external reconnaissance, initial access, internal enumeration, privilege escalation

The cloud-specific addition was this: a new cloud identity means I should re-enumerate everything that identity can access. Credentials are not just a yes-or-no access token. Their permissions, scope, lifetime, and reachable resources all matter.

That approach helped more than trying to remember every AWS service name. I needed to understand identity, exposure, and trust boundaries well enough to reason about a situation I had not seen in exactly the same form.

### Build

Build became much simpler when I stopped treating it as secure coding trivia.

I used the attacker-controlled-input loop for every problem. Identify the input, follow where it goes, identify what consumes it, explain why that use is unsafe, then choose the smallest fix that removes the root cause without breaking normal behavior.

The secure patterns themselves were not exotic. SQL queries should use parameterization. Client-side validation must also be enforced on the server. Finite valid input is a good place for an allowlist. Command execution should avoid building shell strings from user input and use safer APIs. File uploads need server-side validation, content checks, safe generated names, restricted permissions, and storage outside an executable webroot. Protected actions and objects require server-side authorization checks.

The same reasoning applies to cloud configuration. IAM should follow least privilege. Exposed long-lived credentials should be rotated, and temporary, scoped credentials should be preferred where possible.

The hard part is not reciting those sentences. It is recognizing which boundary failed and selecting a fix that actually belongs at that boundary.

### My Offline Notes

I built a local offline reference system from my SEC-100 material on my Omarchy Linux host, rooted at `/home/aymen/oscc-sec100`. I wanted one place I could search without repeatedly going back through the course website while preparing.

It ended up being much more complete than I expected: 40 modules, 182 lesson pages, 166 video transcripts, 385 exercises, 735 source-derived pages preserved, and 373 localized images. I checked it for completeness and ended with zero missing course content and zero broken local links or images.

I also made Neovim-friendly Markdown cheat sheets for Attack, Defend, Build, networking, firewalling, cloud, Linux, Windows, Splunk, remediation, and secure coding.

Plain Markdown was deliberate. LLMs are forbidden during the exam, so I did not want preparation built around a tool I could not use when it mattered. My planned setup was simple: Omarchy, the OffSec VPN, a browser, Burp Suite, a terminal, Neovim, and local notes. No ChatGPT, Gemini, KAI, or any other LLM.

The offline system was probably overkill. Still, building it removed the feeling that I might be unable to find something under pressure. In the actual exam, I barely needed most of it.

## Exam Day

I joined the proctoring process early and used the setup I had already planned: Omarchy Linux, the OffSec VPN, browser, Burp Suite, terminal, Neovim, and my local Markdown cheat sheets.

The exam allows up to six hours. I completed it in 1 hour and 57 minutes, so I never felt serious time pressure.

Attack felt comfortable because of my existing offensive background. The preparation I had done around root cause and remediation paid off in Defend. Build was also much easier once I approached each problem with the same input, flow, consumer, root cause, and correct-fix questions.

I did not need the majority of the notes I had prepared. That was slightly funny after the amount of work I put into them, but it also meant the preparation had done its job before the exam. I was not learning concepts while the clock was running.

From my attempt, the exam felt fair relative to the course objectives. That is a personal judgment, and I am deliberately not describing individual tasks.

## My Result

My final score was 90 out of 90, with 100% in Attack, 100% in Defend, and 100% in Build. My total time was 1 hour and 57 minutes out of the available six hours.

<p align="center">
  <img src="/images/oscc_points_time.jpeg" alt="OSCC-SEC exam result showing 90 out of 90 points and completion in 1 hour 57 minutes" />
</p>

I also received the official OSCC certificate, earned on September 10, 2026. The certification is valid for three years, through September 9, 2029. It can be checked on my [official OffSec credential page](https://credentials.offsec.com/fca4ff5f-27c5-4afe-bc59-430596f4217e#acc.bA4dEBo8). OffSec also explains the three-year validity and renewal options in its [CyberCore FAQ](https://help.offsec.com/hc/en-us/articles/27747560060180-CyberCore-FAQ).

<p align="center">
  <a href="https://credentials.offsec.com/fca4ff5f-27c5-4afe-bc59-430596f4217e#acc.bA4dEBo8">
    <img src="/images/oscc-certificate.png" alt="Aymen Drid OffSec CyberCore Certified OSCC-SEC certificate" />
  </a>
</p>

## How Difficult Was It?

For me personally, the exam felt comfortable. I would not turn that into the general statement that OSCC is easy.

It felt easy for me because of what I had already done before sitting it: the HTB Web Penetration Tester path, most of CPTS, many HTB machines, SEC-100, focused Defend remediation practice, Build review, and cloud review. That is quite a bit of preparation for a fundamentals certification.

Somebody coming directly from SEC-100 without additional hands-on practice may have a very different experience. Even among people with offensive experience, Defend and Build can expose gaps that do not appear while solving boxes. Difficulty depends on which of the three perspectives a person has already practiced.

So my honest answer is yes, OSCC felt easy for me. The reason matters more than the answer.

## What I Overprepared

I probably overprepared.

I made more remediation cards and notes than I ended up needing. I worried about Attack longer than necessary. I built a very complete offline reference system and then barely consulted most of it during the exam.

I do not regret doing it. The extra preparation removed uncertainty and made the exam calm. But if the goal is efficiency, I could have reached that calm point sooner.

There is always another box to solve and another page of notes to improve. At some point, that stops addressing a real weakness and becomes a way to delay choosing an exam date. I was getting close to that point with Attack.

## What I Would Do Differently

If I prepared again with the same background, I would spend less time worrying about Attack. CPTS and Web Penetration Tester experience were already strong preparation for that section.

I would move earlier into focused Defend practice, especially root-cause remediation and verification. I would practice Build as a series of decisions rather than memorize definitions. For cloud, I would continue focusing on identity, permissions, credentials, and exposure instead of memorizing service lists.

I would also build concise notes sooner. My complete offline reference was useful for confidence, but a smaller set of well-organized Markdown pages was what I was most likely to use during the exam.

Most importantly, I would stop endlessly solving boxes just to feel more ready. Once I could enumerate fresh targets without a walkthrough and reason through Defend and Build scenarios, taking the exam was more useful than chasing a perfect feeling of readiness.

## Advice for Future Candidates

Understand the course rather than memorizing exercise answers. The exam is much easier to reason through when you understand why something is vulnerable and why a fix works.

Be comfortable enumerating without a walkthrough. You do not need to know every command from memory, but you should be able to move from an unfamiliar target to sensible hypotheses on your own.

For Defend, learn the difference between containment, eradication, remediation, recovery, and verification. Always identify the root cause. Practice fixing vulnerabilities while preserving the intended function, because disabling a required service is usually not the same as securing it.

For Build, learn secure patterns rather than memorizing code snippets. Follow attacker-controlled data and look for the trust boundary that failed. A small, correct server-side fix is better than a cosmetic check in the wrong place.

Learn enough cloud to understand EC2, S3, IAM, permissions, exposure, and credentials. You do not need to recite an AWS catalog. You do need to understand who can access what, from where, and for how long.

Keep notes searchable and simple. Use tools you will actually be allowed to use during the exam. Also, do not overcomplicate entry-level problems. Check the direct explanation before inventing a complicated one.

Finally, once you reach a realistic readiness threshold, take the exam. Preparing forever does not remove all uncertainty.

## Was OSCC Worth It?

For me, yes, especially because I got the opportunity through the CTF with Trojeun.

The Attack material did not add much depth beyond my existing offensive study, but I did gain knowledge on the defensive side and in cloud security fundamentals. Defend helped me get better at thinking through incident response, finding the root cause, and fixing the weakness that allowed an attack. The cloud material gave me a clearer understanding of IAM permissions, exposed resources, credentials, and shared responsibility. Those were useful additions to my mostly offensive background.

I also liked having to think across attacker, defender, and builder roles. Build made secure coding feel less like a list of vulnerability names and more like following trust through a system.

I think OSCC fits beginners who want structured cybersecurity fundamentals, people who want hands-on exposure across offensive, defensive, and secure-build work, and students looking for a foundation before deeper certifications.

If someone is already deep into CPTS or OSCP-level offensive content, I would not choose OSCC expecting a difficult pentesting exam. I would choose it for broad validation and for the parts outside pure exploitation.
