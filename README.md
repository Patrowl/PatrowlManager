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
Information, news and updates are regularly posted on [Patrowl.io Twitter account](https://twitter.com/patrowl_io) and on [the  blog](https://blog.patrowl.io/).

# Contributing
Please see our [Code of conduct](https://github.com/Patrowl/PatrowlDocs/blob/master/support/code_of_conduct.md). We welcome your contributions. Please feel free to fork the code, play with it, make some patches and send us pull requests via [issues](https://github.com/Patrowl/PatrowlManager/issues).

# Roadmap
- [X] API Documentation
- [X] Python 3 migration
- [ ] Transform all API calls to async tasks (limit Nginx 504 timeouts)
- [X] Beautify scan creation and edition forms
- [ ] Enhance finding states management
- [ ] Enhance user management
- [ ] Support scan campaigns (multiple scan definition)
- [X] Support django-health-check
- [ ] Support cache
- [X] Optimize global performances
- [ ] Refactor static files (remove unused ?)
- [X] Continuous Docker image deployment (DockerHub)

Follow our roadmap on Trello [here](https://trello.com/b/rksoIN5y)

# Support
Please [open an issue on GitHub](https://github.com/Patrowl/PatrowlManager/issues) if you'd like to report a bug or request a feature. We are also available on [Gitter](https://gitter.im/Patrowl/Support) to help you out.

If you need to contact the project team, send an email to <getsupport@patrowl.io>.

# Commercial Services
Looking for advanced support, training, integration, custom developments, dual-licensing ? Contact us at getsupport@patrowl.io

# Security contact
Please disclose any security-related issues or vulnerabilities by emailing security@patrowl.io, instead of using the public issue tracker.

# Copyright
Copyright (C) 2018-2020 Nicolas MATTIOCCO ([@MaKyOtOx](https://twitter.com/MaKyOtOx) - nicolas@greenlock.fr)

# Travis build status
| Branch  | Status  |
|---|---|
| master | [![Build Status](https://travis-ci.com/Patrowl/PatrowlManager.svg?branch=master)](https://travis-ci.com/Patrowl/PatrowlManager) |
| develop | [![Build Status](https://travis-ci.com/Patrowl/PatrowlManager.svg?branch=develop)](https://travis-ci.com/Patrowl/PatrowlManager) |
