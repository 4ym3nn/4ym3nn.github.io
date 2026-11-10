+++
date = '2026-11-10T12:00:00+01:00'
draft = false
title = 'My CPTS Exam Experience'
description = 'How I prepared for CPTS, the rabbit holes I fell into during the exam, and the things I missed while enumerating.'
hideToc = false
tags = ['CPTS', 'Hack The Box', 'Penetration Testing', 'Review', 'Certification']
+++

I'm finally CPTS certified!

## How I prepared

I started preparing in March 2026, around the time of my first [CRTP attempt](/reviews/crtp-review/). I worked on the Active Directory section of the CPTS path, and after my CRTP exam I went back to the path, solving machines alongside it.

I used the [NetSecFocus Trophy Room sheet](https://docs.google.com/spreadsheets/u/1/d/1dwSMIAPIam0PuRBkCiDI88pU3yzrqqHkDtBngUHNCw8/htmlview) as my main preparation reference. This was how I kept track of the machines I was working through:

![My CPTS preparation tracker, based on the NetSecFocus Trophy Room sheet](preparation-tracker.png)

After working through about 70% of that list, I felt ready and decided to take the exam.

## The exam

I started at 2 p.m. after getting enough sleep. I read the exam letter carefully, then started working on the entry point. Almost immediately, I thought I knew the way forward. Well, that turned out to be a rabbit hole, hehe.

I went through several dead ends because I rushed in without doing my full recon. After a few hours, I finally slowed down and remembered to do the same enumeration I normally do on any machine I solve.

Once I did that, flag 1 came pretty easily. Things went smoothly up to flag 5, but flag 6 kept me stuck for a whole day. That was 24 hours of thinking and enumerating before I finally found a lead. From there, the path to flag 9 was straightforward.

Then I got stuck again. Flag 10 took another day, and the path forward had been right in front of me the whole time. I just hadn't seen it. Once I spotted it, getting to flag 11 was easy.

Flag 12 stopped me again, but this time it was an issue I'd already run into earlier. Once I remembered it, I got moving again.

I lost a lot of time chasing dead ends or missing details during enumeration. Even when I thought I knew where to go, I still needed to slow down and check properly.

And a big thank you to @kanyo for pushing me to take it. Your motivation helped me make that decision, and I really appreciate it.

## What I'd do differently if I started over

### Get comfortable with enterprise networks

For me, the exam felt pretty similar to the enterprise network skills assessment. Get your hands dirty there so you aren't still trying to understand how that kind of environment is structured during the exam. Getting used to working across multiple networks and figuring out how they connect makes it easier to see where to go next.

I'd also focus heavily on the concepts taught in the course. Make sure you understand every skills assessment, rather than just knowing how to repeat the solution.

### Quality over quantity

I'd rather complete the CPTS path with my full attention and understand every step of an attack than solve 100 machines while only half understanding what I did.

Solving more machines is good, of course. Just don't make getting the flag your only goal. Ask yourself: why does this work here? What would happen if X changed? If something failed and you don't know why, come back to it after finishing the machine and work it out.

Work through the whole path, from footprinting to reporting and the final enterprise network assessment. Take notes as you go, and actually practise what you've learned. Reading about something without trying it yourself makes it much easier to forget.

### Write as you go

The reporting module is easy to underestimate. It teaches you to document your work as you go, rather than waiting until you've finished the exam to start writing everything up.

I'd also make a habit of writing up every practice machine. Getting used to explaining what you did, and why, makes the exam report much easier to put together.

### Find tools that work for you

The `tmux`/`nvim` combo helped me a lot. `tmux` made it easier to split my terminal, log sessions, and move between windows. `nvim` made selecting, copying, and pasting text much more straightforward. Big thanks to [@hxuu](https://vhxuu.xyz/) for introducing me to both.

Find whatever tools feel comfortable for you and get used to them before the exam. Imagine fighting your mouse just to copy a long Base64 string during CPTS. You already have enough problems to deal with; that doesn't need to be another one.

## Resources I used

These are the resources I used alongside the course:

- [NetSecFocus Trophy Room sheet](https://docs.google.com/spreadsheets/u/1/d/1dwSMIAPIam0PuRBkCiDI88pU3yzrqqHkDtBngUHNCw8/htmlview): my main reference for choosing practice machines.
- [My HTB machine notes](https://github.com/4ym3nn/htb-machine-notes/blob/main/Main.md): a searchable index of machine notes, including user and root paths.
- [My pentesting cheat sheets](https://github.com/4ym3nn/cheat-papers): references for enumeration, privilege escalation, Active Directory, and reporting.

## The certificate

I earned my HTB Certified Penetration Testing Specialist (CPTS) certification on November 10, 2026.

[![My HTB Certified Penetration Testing Specialist certificate, issued to Aymen Drid on November 10, 2026](cpts-certificate.png)](cpts-certificate.pdf)

[View the certificate (PDF)](cpts-certificate.pdf)
