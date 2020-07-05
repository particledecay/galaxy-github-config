# galaxy-github-config
An Ansible Galaxy role for declarative configuration of GitHub teams, repos, and settings.

## Installation
Install via Ansible Galaxy:
```bash
ansible-galaxy install particledecay.github_config
```

## Usage
All options are defined under a top-level `github_config` var. Define your GitHub organization under an `orgs` var, and then `global`, `teams`, and/or `repos` keys under your org with their own settings.


```yaml
github_config:
  token: {{ my_github_token }}
  url: https://mycompany.github.com/api/v3  # optional
  orgs:
    MyOrg:
      global:
        access:
          - team: 1234567  # all of MyOrg's technology team gets read-only
            permission: pull
          - team: 3434343
            permission: admin
        allow_merge_commit: False
        allow_rebase_merge: False
        allow_squash_merge: True
        default_branch_protection:
          required_status_checks:
            - WIP
          enforce_admins: True
      teams:
        - id: 3434343
          name: Admins
          description: Governance team with admin access to GitHub settings
          members:
            - particledecay
            - some_other_person
      repos:
        - name: myorg-main-repo
          description: Serve company marketing pages
        - name: myorg-backend-repo
          description: Data-backed API for company
```

There are too many options to list so please check out [the module's readme](https://github.com/particledecay/ansible-github-config/blob/master/README.md#configuration) for a more comprehensive guide to org options.
