# TenantReporter
## Summary
The TenantReporter is an internal [Arribatec](https://arribatec.com) tool used to gather as much information as possible about an Azure environment prior to a technical migration. 

The goal is to parse this into a HTML file for an easy overview of what an environment contains, the current version only outputs to the console. 

## Data collected
Below is an overview of what kind of data we'll collect in this script. 

### Exchange
- Mailbox (user) data
  - Number of mailboxes
  - Individual and collective size of all mailboxes
 
- Distribution lists
- Shared Mailboxes
- Aliases
- Forwarding

### Azure AD
- Office 365 Groups
- Security Groups
- Conditional Access policies
- Number of guest users
- App registrations


### SharePoint
- Number of sites
- Data stored on each site
- Data stored on all sites in Total
- External sharing

### Teams
- Number of Teams
- Number of Teams with guests
- amount of data stored in Teams.



Pulls all relevant data about tenant to minimize clicking around in Azure. 
