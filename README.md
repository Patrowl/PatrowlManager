![](https://github.com/Patrowl/PatrowlDocs/blob/master/images/logos/logo-patrowl-light.png)

[![Join the chat at https://gitter.im/Patrowl/Support](https://badges.gitter.im/Patrowl/Support.png)](https://gitter.im/Patrowl/Support)
[![Known Vulnerabilities](https://snyk.io/test/github/Patrowl/PatrowlManager/badge.svg)](https://snyk.io/test/github/Patrowl/PatrowlManager)
![SonarCloud](https://sonarcloud.io/api/project_badges/measure?project=patrowl-manager&metric=alert_status)
[![Build Status](https://travis-ci.com/Patrowl/PatrowlManager.svg?branch=master)](https://travis-ci.com/Patrowl/PatrowlManager)
[![Codacy Badge](https://api.codacy.com/project/badge/Grade/524eab1787ba4a8dbff03f6f59c93b33)](https://www.codacy.com/app/MaKyOtOx/PatrowlManager)
[![Rawsec's CyberSecurity Inventory](https://inventory.rawsec.ml/img/badges/Rawsec-inventoried-FF5050_popout_without_logo.svg)](https://inventory.rawsec.ml/)



# **PatrOwl**
[PatrOwl](https://www.patrowl.io/) is a scalable, free and open-source solution for orchestrating Security Operations.  
**PatrowlManager** is the Front-end application for managing the assets, reviewing risks on real-time, orchestrating the operations (scans, searches, API calls, ...), aggregating the results, relaying alerts on third parties (ex: Incident Response platform like [TheHive](https://github.com/TheHive-Project/TheHive/), Splunk, ...) and providing the reports and dashboards. Operations are performed by the [PatrowlEngines](https://github.com/Patrowl/PatrowlEngines/) instances. Don't forget to install and deploy them ;)

# Project pitch desk
[![PatrOwl Pitch Desk](https://github.com/Patrowl/PatrowlDocs/blob/master/images/misc/pitch-desk-frontpage.png)](https://docs.google.com/presentation/d/1bYUYzsGZBQJrq193rz98wIgjZam7y2vaBQ7C2uS0HaM/edit#slide=id.p)

# Try it now!
To try PatrOwl, install it by reading the [Installation Guide](https://github.com/Patrowl/PatrowlDocs/blob/master/installation/installation-guide.md) and the [User Guide](https://github.com/Patrowl/PatrowlDocs/blob/master/installation/user-guide.md).

# Architecture
Fully-Developed in Python, PatrOwl is composed of a Front-end application **PatrowlManager** (Django) communicating with one or multiple **PatrowlEngines** micro-applications (Flask) which perform the scans, analyze the results and format them in a normalized way. It remains incredibly easy to customize all components. Asynchronous tasks and engine scalability are supported by RabbitMQ and Celery.
![Architecture](https://github.com/Patrowl/PatrowlDocs/blob/master/images/userguide/technical-overview.png)  
The PatrowlManager application is reachable using the embedded WEB interface or using the JSON-API. PatrowlEngines are only available through generic JSON-API calls (see Documentation).

# License
PatrOwl is an open source and free software released under the [AGPL](https://github.com/Patrowl/PatrowlManager/blob/master/LICENSE) (Affero General Public License). We are committed to ensure that PatrOwl will remain a free and open source project on the long-run.

# Updates
Information, news and updates are regularly posted on [Patrowl.io Twitter account](https://twitter.com/patrowl_io).

# Contributing
Please see our [Code of conduct](https://github.com/Patrowl/PatrowlDocs/blob/master/support/code_of_conduct.md). We welcome your contributions. Please feel free to fork the code, play with it, make some patches and send us pull requests via [issues](https://github.com/Patrowl/PatrowlManager/issues).

# Roadmap
- [ ] Enhance finding states management
- [ ] Support scan campaigns (multiple scan definition at once)
- [ ] Support cache
- [ ] Refactor static files (remove unused ?)

Follow our public roadmap on Trello [here](https://trello.com/b/rksoIN5y)

# Support
Please [open an issue on GitHub](https://github.com/Patrowl/PatrowlManager/issues) if you'd like to report a bug or request a feature. We are also available on [Gitter](https://gitter.im/Patrowl/Support) to help you out.

If you need to contact the project team, send an email to <getsupport@patrowl.io>.

# Pro Edition and SaaS
A commercial Pro Edition is available and officially supported by the PatrOwl company. It includes following extra and awesome features:
- [x] Advanced user management
- [x] RBAC: Multiple roles are supported to restrict users privileges on features
- [x] Multi-tenancy: assets and scans results can be shared with user teams
- [x] 3rd party authentication: Azure Active Directory, ADFS (Windows 2012 and 2016), LDAP
- [x] Terraform+Ansible deployment scripts
- [x] Pro Engines including: ZAP, Nikto, Microsoft Cloud App Security, CloudSploit and Onyphe
- [x] Pro Support
- [ ] Autonomous asset discovery (in progress, planned to Q2 2021)
- [ ] Vulnerability prioritization (in progress, planned to Q1 2021)
- [ ] Ticketing system integration, including JIRA, ServiceNow, ZenDesk and GLPI (in progress, planned to Q2 2021)

This version is also available on the official SaaS platform.
See: https://patrowl.io/get-started

# Commercial Services
Looking for advanced support, training, integration, custom developments, dual-licensing ? Contact us at getsupport@patrowl.io

# Security contact
Please disclose any security-related issues or vulnerabilities by emailing security@patrowl.io, instead of using the public issue tracker.

# Copyright
Copyright (C) 2018-2021 Nicolas MATTIOCCO ([@MaKyOtOx](https://twitter.com/MaKyOtOx) - nicolas@greenlock.fr)

# Travis build status
| Branch  | Status  |
|---|---|
| master | [![Build Status](https://travis-ci.com/Patrowl/PatrowlManager.svg?branch=master)](https://travis-ci.com/Patrowl/PatrowlManager) |
| develop | [![Build Status](https://travis-ci.com/Patrowl/PatrowlManager.svg?branch=develop)](https://travis-ci.com/Patrowl/PatrowlManager) |
