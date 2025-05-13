# Security Policy

This document outlines security policy and procedures for the CrowdStrike `goFalcon` project.

## Reporting a potential security vulnerability

We have multiple avenues to receive security-related vulnerability reports.

Please report suspected security vulnerabilities by:

> [!IMPORTANT]
> Please do not include any sensitive information in the bug created in github. They should instead be sent to __oss-security@crowdstrike.com__.

+ Submitting a [bug](https://github.com/CrowdStrike/gofalcon/issues/new).
+ Sending an email to __oss-security@crowdstrike.com__.

## Disclosure and mitigation process

Upon receiving a security bug report, the issue will be assigned to one of the project maintainers. This person will coordinate the related fix and release process, involving the following steps:
+ Communicate with you to confirm we have received the report and provide you with a status update.
    - You should receive this message within 48 - 72 business hours.
+ Confirmation of the issue and a determination of affected versions.
+ An audit of the codebase to find any potentially similar problems.
+ Preparation of patches for all releases still under maintenance.
    - These patches will be submitted as a separate pull request and contain a version update.
    - This pull request will be flagged as a security fix.

## Comments

If you have suggestions on how this process could be improved, please let us know by [starting a new discussion](https://github.com/CrowdStrike/gofalcon/discussions).
