New features/fixes in the latest update
=====================================

June 29, 2018
---
* FEATURE: None
* FIX: None
* DOC: Updating RELEASE.md and .gitignore files
* MISC: None

June 29, 2018
---
* FEATURE: None
* FIX: None
* DOC: None
* MISC: Final commit before refactoring source code repo

June 20, 2018
---
* FEATURE: Adding custom tags on assets and asset groups
* FIX: owl_leaks Dockerfile (import utils)
* DOC: Update the installation guides
* DOC: Adding AGPLv3.0 Licences to backend and engines projects

June 5, 2018
---
* FEATURE: add pagination in findings and events tabs inside the detailed view of a scan
* FIX: Export assets errors (encoding + asset group selection)
* FIX: Stop scan

April 30, 2018
---
* Finding list: filter per references + pagination
* Reference links: support CVE-SEARCH (CIRCL.LU)

April 19, 2018
---
* Add comments (free text) to findings

April 16, 2018
---
* New engine: 'owl_code' for static code review. Support Retire.js for source code located on the unix filesystem, SVN+HTTP(S) and GIT+HTTP(S) repos

April 12, 2018
---
* FIX: no autorefresh engines statuses until authentication succeeded
* Search bar in scan details view
* Quick actions on findings scan details: change status or severity, export to JSON/STIX/HTML, delete, send alerts Slack/TheHive/Mail
* Nmap engine: multi-threading refactoring
* Update backend requirements.txt (thehive4py)

April 5, 2018
---
* Adding website www.survivowl.io

March 14, 2018
---
* New engine: "owl_leaks" aims at search data leaks on the web, the dark web and the deep web (social networks, source code repo, pasties, ...) using keywords. Support only GitHub for now.

March 9, 2018
---
* Upgrade to Django 1.11: upgrade django-celery-beat & deps, adding on_delete attributes on ForeignKey definitions
* Engines support debug mode
* Fixes in tasks
* Development roadmap (1st version)

February 24, 2018
---
* Performance: add EnginePolicyScopes to findings in order to enhance stats calculation on asset/asset group detailed views
* Dockerize Arachni, Cortex and owl_dns engines

February 20, 2018
---
* Dockerize Censys, Cortex, Nessus, Nmap, SSL-LABS, URLVoid and VT engines

February 14, 2018
---
* Adding related events in scan detailled view
* Update asset and asset groups HTML report templates
* Footer: auto-update engines status and running scans counter every 5 seconds

February 13, 2018
---
* SSL-Labs, URLVoid, VT Engines: support multi-threading + multi-hosts
* Asset listing: adding "reset filters" button + field search
* Asset details: adding direct links to related scans, remediations, investigation links and owners

February 11, 2018
---
* Nmap Engine: support multi-threading

February 2, 2018
---
* FIX: create media dir if not exists when importing scan policies w/ files

February 2, 2018
---
* integration fixes (supervisord config + dirs)

February 2, 2018
---
* export finding using STIX or JSON formats
* quick search & filter & sort on asset listing (todo: asset group listing)

January 26, 2018
---
* Adding quick engine status in footer
* Footer always at the bottom
* FIX issues:
  #1: 'Invalid json'

January 25, 2018
---
* Dashboard refactoring

January 23, 2018
---
* Adding cortex engine (select analyzers list, meta-analyzers or all analyzers available with datatype)

January 18, 2018
---
* Cortex analyzer to get asset report + report templates
* API authentication (Basic & Session) to /assets/api/v1/details/*
* Update finding infos on demand

January 17, 2018
---
* Alerts: Duplicate alert rule, Support alert notifications to email, Add severity to alert rule
* Add & Delete setting
* Add a minimalistic footer to all pages

January 16, 2018
---
* Start a scan on asset group
* Show asset group details on views for scan definition and scan performed
* Prettify views for adding new scan, new asset and new asset group
* Create alert rules
* Support alert notifications to events, TheHive and Slack

January 9, 2018
---
* Delete multiple selected assets in list view
* Prettify findings and scan detailed views

January 5, 2018
---
* Refactor asset grade management (performance improvement)
* Show new and missing findings on scan definition views
* nmap engine: trim asset name

October, 2017
---
* BO/Asset & AssetsGroups: Calculate risk grade + trends in details + risk grade in listing
* BO/Asset: Chart on asset security trends (asset details)

October 19, 2017
---
* BO/Events: List events in a JS/Datatable
* BO/Assets: export asset report in json
* BO/AssetsGroups: adding template for a detailed view
* BO/Assets & AssetsGroups: Adding quick report tags on detailed view
* Engines: Fix issues on VT & Dns engines

October 5, 2017:
---
* Export policy file (json format) for selected policies
* Adding Settings App

September 18, 2017:
---
* New component for logging: Event
* Logging object creation, updating and deletion
* Adding censys engine
* Nmap & Nessus engines: adding installation notes
* Nmap & Nessus engines: adding options support (host, port, debug) on start
