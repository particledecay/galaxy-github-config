#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2019, Joey Espinosa <jlouis.espinosa@gmail.com>
# Copyright: (c) 2019, Ansible Project
# MIT License (https://opensource.org/licenses/MIT)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

ANSIBLE_METADATA = {'metadata_version': '1.1', 'status': ['preview'], 'supported_by': 'community'}

DOCUMENTATION = r'''
---
module: github_config
author: "Joey Espinosa (@ParticleDecay)"
short_description: Interact with GitHub's API
requirements:
    - pygithub
version_added: "2.10"
description:
    - Change GitHub settings using GitHub APIv3
options:
    token:
        description:
            - The GitHub token for API access
        required: True
        type: str
    path:
        description:
            - The path to the GitHub settings
        required: False
        type: str
    config:
        description:
            - The full GitHub config
        required: False
        type: dict
    url:
        description:
            - URL to the GitHub API (if Enterprise)
        required: False
        type: str
'''

EXAMPLES = r'''
#  This example uses the following config
#  MyOrg:
#    global:
#      access:
#        - team: 1234567
#          permission: admin
#      default_branch: develop
#    teams:
#      - id: 1234567
#        name: Administrators
#        description: Developers with administrative privileges
#        members:
#          - superman
#          - batman
#          - wonderwoman
#    repos:
#      - name: foo-bar
#        description: A repo that does stuff

- name: apply github config
  github_config:
    token: "{{ github_token }}"
    path: /path/to/github/config.yaml

- name: apply github config for a github enterprise server
  github:
    token: "{{ github_token }}"
    config: "{{ github_config_as_vars }}"
    url: https://github.mycompany.com/api/v3
'''

RETURN = r'''
changed:
    description: whether the GitHub settings were modified
    returned: always
    type: bool
'''

import functools
import json
import os
from urllib3.exceptions import ReadTimeoutError

from ansible.module_utils import basic
from ansible.module_utils._text import to_bytes
from requests.exceptions import ReadTimeout
from github import BadCredentialsException, Github, GithubException
try:
    from yaml import load, CLoader as Loader
except ImportError:
    from yaml import load, Loader


def set_module_args(args):
    """For dynamic module args (such as for testing)."""
    args = json.dumps({'ANSIBLE_MODULE_ARGS': args})
    basic._ANSIBLE_ARGS = to_bytes(args)


class GithubManager:
    """Manage the GitHub API interactions."""

    def __init__(self, module):
        """Initialize module and validate config."""
        self.module = module
        self.config = self.module.params['config']
        self.path = self.module.params['path']
        self.token = self.module.params['token']
        self.api_url = self.module.params['url']
        self.dry_run = self.module.check_mode

        # this will hold the github connection
        self._github = {}
        self._all_teams = []

        # we need one of these
        if not self.config and not self.path:
            self.module.fail_json(msg="missing required config path or vars")

        if not self.config:
            if os.path.isfile(self.path):
                read_result = self.read_config(self.path)
                if read_result is not True:
                    self.module.fail_json(msg=read_result)
            else:
                self.module.fail_json(msg="could not find file at '%s'" % self.path)

        # if we don't have a config by this point, fail
        if not self.config:
            self.module.fail_json(msg="could not parse config")

        try:
            validated = self.validate()
        except (ReadTimeout, ReadTimeoutError) as err:
            self.module.fail_json(msg="timed out while requesting from github: %s" % err)

        if validated is not True:
            self.module.fail_json(msg=validated)

    def _create_mod(self, mod_type, func, **kwargs):
        """Return an appropriate modification object for the GitHub changes."""
        if self.dry_run:
            return {"type": f"{mod_type}:{func.__name__}", **kwargs}
        return functools.partial(func, **kwargs)

    def run(self):
        """Assess changes in GitHub configuration and execute them."""
        modified = False
        try:
            mods, modified = self.get_all_mods()
        except (ReadTimeout, ReadTimeoutError) as err:
            self.module.fail_json(msg="timed out while requesting from github: %s" % err)
        result = {'changed': modified}
        if not self.dry_run:
            for mod in mods:
                try:
                    mod()
                except (ReadTimeout, ReadTimeoutError) as err:
                    self.module.fail_json(msg="timed out while applying a change in github: %s" % err)
        else:
            result['mods'] = mods
            result['dry_run'] = self.dry_run
        return result

    def read_config(self, path):
        """Read file with GitHub config and save it."""
        try:
            with open(path) as f:
                self.config = load(f, Loader=Loader)
        except (IOError, OSError, ValueError):
            return "there was an error while reading '%s'" % path

        return True

    def validate(self):
        """Return True if a valid token and config has been supplied."""
        # try logging in
        g = Github(self.token)
        try:
            gu = g.get_user()
            self._github['user'] = gu
        except BadCredentialsException:
            return "unable to authenticate with supplied token"

        # check the values
        self._github['orgs'] = {}
        self._github['repos'] = {}
        self._github['teams'] = {}
        orgs = gu.get_orgs()
        for org in self.config:
            # save the org
            try:
                self._github['orgs'][org] = next(filter(lambda o, org=org: o.login == org, orgs))
            except StopIteration:
                return "org '%s' not found in GitHub account" % org

            self._github['repos'][org] = {}
            self._github['teams'][org] = {}

            # check the repos
            repos = self._github['orgs'][org].get_repos()
            for repo in self.config[org].get('repos', []):
                # save the repo
                try:
                    self._github['repos'][org][repo['name']] = next(
                        filter(lambda r, repo=repo: r.name == repo['name'], repos))
                except StopIteration:
                    return "repo '%s' not found in '%s' org" % (repo['name'], org)
                except KeyError:
                    return "repo missing required 'name' attribute"

            # check the teams
            self._all_teams = self._github['orgs'][org].get_teams()
            for team in self.config[org].get('teams', []):
                # save the team
                try:
                    self._github['teams'][org][team['id']] = next(
                        filter(lambda t, team=team: t.id == team['id'], self._all_teams))
                except StopIteration:
                    return "team '%s' not found in '%s' org" % (team['id'], org)
                except KeyError:
                    return "team missing required 'id' attribute"

        return True

    def get_team_mods(self):
        """Return modifications to be performed for teams."""
        mods = []

        for org, teams in self._github['teams'].items():
            config = self.config[org]
            for team_config in config.get('teams', {}):
                modified = False
                team = teams[team_config['id']]

                # check name, description, permission, privacy
                edit_team = {}
                if team_config.get('name') is not None:
                    edit_team['name'] = team_config['name']
                    if team_config['name'] != team.name:
                        modified = True
                if team_config.get('description') is not None:
                    edit_team['description'] = team_config['description']
                    if team_config['description'] != team.description:
                        modified = True
                if team_config.get('permission') is not None:
                    edit_team['permission'] = team_config['permission']
                    if team_config['permission'] != team.permission:
                        modified = True
                if team_config.get('privacy') is not None:
                    edit_team['privacy'] = team_config['privacy']
                    if team_config['privacy'] != team.privacy:
                        modified = True

                # update name, description, permission, privacy
                if modified:
                    mods.append(self._create_mod(mod_type='team', func=team.edit, **edit_team))

                # check membership
                members = team.get_members()
                member_logins = [m.login for m in members]
                # these members need to be added
                to_be_added = set(team_config['members']).difference(member_logins)
                # these members need to be removed
                to_be_removed = set(member_logins).difference(team_config['members'])

                # update membership
                if to_be_added or to_be_removed:
                    all_members = self._github['orgs'][org].get_members()
                    modified = True
                for login in to_be_added:
                    try:
                        member = next(filter(lambda m, login=login: m.login == login, all_members))
                    except StopIteration:
                        self.module.fail_json(msg="'%s' does not exist as a member in the '%s' org" % (login, org))
                    mods.append(self._create_mod(mod_type='team', func=team.add_membership, member=member))
                for login in to_be_removed:
                    member = next(filter(lambda m: m.login == login, members))
                    mods.append(self._create_mod(mod_type='team', func=team.remove_membership, member=member))

        return mods, modified

    def get_repo_mods(self):
        """Return modifications to be performed for repos."""
        mods = []

        for org, repos in self._github['repos'].items():
            config = self.config[org]
            global_config = config.get('global', {})
            for repo_config in config.get('repos', {}):
                modified = False
                repo = repos[repo_config['name']]

                # check name, description, multiple standard repo settings
                edit_repo = {'name': repo_config['name']}
                homepage = repo_config.get('homepage', global_config.get('homepage'))
                if homepage is not None:
                    edit_repo['homepage'] = homepage
                    if homepage != repo.homepage:
                        modified = True
                private = repo_config.get('private', global_config.get('private'))
                if private is not None:
                    edit_repo['private'] = private
                    if private != repo.private:
                        modified = True
                has_issues = repo_config.get('has_issues', global_config.get('has_issues'))
                if has_issues is not None:
                    edit_repo['has_issues'] = has_issues
                    if has_issues != repo.has_issues:
                        modified = True
                has_projects = repo_config.get('has_projects', global_config.get('has_projects'))
                if has_projects is not None:
                    edit_repo['has_projects'] = has_projects
                    if has_projects != repo.has_projects:
                        modified = True
                has_wiki = repo_config.get('has_wiki', global_config.get('has_wiki'))
                if has_wiki is not None:
                    edit_repo['has_wiki'] = has_wiki
                    if has_wiki != repo.has_wiki:
                        modified = True
                has_downloads = repo_config.get('has_downloads', global_config.get('has_downloads'))
                if has_downloads is not None:
                    edit_repo['has_downloads'] = has_downloads
                    if has_downloads != repo.has_downloads:
                        modified = True
                default_branch = repo_config.get('default_branch', global_config.get('default_branch'))
                if default_branch is not None:
                    edit_repo['default_branch'] = default_branch
                    if default_branch != repo.default_branch:
                        modified = True
                allow_squash_merge = repo_config.get('allow_squash_merge', global_config.get('allow_squash_merge'))
                if allow_squash_merge is not None:
                    edit_repo['allow_squash_merge'] = allow_squash_merge
                    if allow_squash_merge != repo.allow_squash_merge:
                        modified = True
                allow_merge_commit = repo_config.get('allow_merge_commit', global_config.get('allow_merge_commit'))
                if allow_merge_commit is not None:
                    edit_repo['allow_merge_commit'] = allow_merge_commit
                    if allow_merge_commit != repo.allow_merge_commit:
                        modified = True
                allow_rebase_merge = repo_config.get('allow_rebase_merge', global_config.get('allow_rebase_merge'))
                if allow_rebase_merge is not None:
                    edit_repo['allow_rebase_merge'] = allow_rebase_merge
                    if allow_rebase_merge != repo.allow_rebase_merge:
                        modified = True
                delete_branch_on_merge = repo_config.get('delete_branch_on_merge',
                                                         global_config.get('delete_branch_on_merge'))
                if delete_branch_on_merge is not None:
                    edit_repo['delete_branch_on_merge'] = delete_branch_on_merge
                    if delete_branch_on_merge != repo.delete_branch_on_merge:
                        modified = True

                # update name, description, multiple standard repo settings
                if modified:
                    mods.append(self._create_mod(mod_type='repo', func=repo.edit, **edit_repo))

                #  # security settings
                #  automated_security_fixes = repo_config.get('automated_security_fixes', global_config.get('automated_security_fixes'))
                #  if automated_security_fixes is not None:
                #      if automated_security_fixes:
                #          mods.append(self._create_mod(mod_type='repo', func=repo.enable_automated_security_fixes))
                #      else:
                #          mods.append(self._create_mod(mod_type='repo', func=repo.disable_automated_security_fixes))
                #  vulnerability_alert = repo_config.get('vulnerability_alert', global_config.get('vulnerability_alert'))
                #  if vulnerability_alert is not None and vulnerability_alert != repo.get_vulnerability_alert():
                #      if vulnerability_alert:
                #          mods.append(self._create_mod(mod_type='repo', func=repo.enable_vulnerability_alert))
                #      else:
                #          mods.append(self._create_mod(mod_type='repo', func=repo.disable_vulnerability_alert))

                # branch protection
                default_branch = default_branch or repo.default_branch
                try:
                    branch = repo.get_branch(default_branch)
                except GithubException as err:
                    self.module.fail_json(msg="error while retriving branch '%s': %s" % (default_branch, err))
                default_branch_protection = repo_config.get('default_branch_protection',
                                                            global_config.get('default_branch_protection'))
                if default_branch_protection is not None:
                    modified_protection = False
                    try:
                        protection = branch.get_protection()
                    except GithubException:  # no protection enabled
                        try:
                            branch.edit_protection(True)
                            protection = branch.get_protection()
                        except GithubException:  # something else went wrong
                            self.module.fail_json(msg=f"could not enable branch protection for {branch.name} on {repo}")
                    edit_protection = {}

                    # required status checks
                    required_status_checks = default_branch_protection.get('required_status_checks')
                    if required_status_checks is not None:
                        edit_protection['contexts'] = required_status_checks
                        # these checks need to be added
                        checks_missing = set(required_status_checks).difference(
                            getattr(protection.required_status_checks, 'contexts', []))
                        # these members need to be removed
                        too_many_checks = set(getattr(protection.required_status_checks, 'contexts',
                                                      [])).difference(required_status_checks)
                        if checks_missing or too_many_checks:
                            modified_protection = True

                    # enforce admins
                    enforce_admins = default_branch_protection.get('enforce_admins')
                    if enforce_admins is not None:
                        edit_protection['enforce_admins'] = enforce_admins
                        if enforce_admins != protection.enforce_admins:
                            modified_protection = True

                    reviews = default_branch_protection.get('required_pull_request_reviews')
                    if reviews is not None:
                        dismiss_stale_reviews = reviews.get('dismiss_stale_reviews')
                        if dismiss_stale_reviews is not None:
                            edit_protection['dismiss_stale_reviews'] = dismiss_stale_reviews
                            if dismiss_stale_reviews != getattr(protection.required_pull_request_reviews,
                                                                'dismiss_stale_reviews', None):
                                modified_protection = True
                        code_owner_reviews = reviews.get('require_code_owner_reviews')
                        if code_owner_reviews is not None:
                            edit_protection['require_code_owner_reviews'] = code_owner_reviews
                            if code_owner_reviews != getattr(protection.required_pull_request_reviews,
                                                             'require_code_owner_reviews', None):
                                modified_protection = True
                        review_count = reviews.get('required_approving_review_count')
                        if review_count is not None:
                            edit_protection['required_approving_review_count'] = review_count
                            if review_count != getattr(protection.required_pull_request_reviews,
                                                       'required_approving_review_count', None):
                                modified_protection = True

                    if modified_protection:
                        mods.append(self._create_mod(mod_type='branch', func=branch.edit_protection, **edit_protection))
                        modified = True

                # access settings
                accesses = repo_config.get('access', global_config.get('access', []))
                for access in accesses:
                    try:
                        team = next(filter(lambda t, access=access: t.id == access['team'], self._all_teams))
                    except StopIteration:
                        self.module.fail_json(msg="no team found with id '%s'" % access['team'])

                    desired = access.get('permission', 'pull')
                    try:
                        getattr(team.get_repo_permission(repo), desired)
                    except AttributeError:
                        mods.append(
                            self._create_mod(mod_type='repo',
                                             func=team.set_repo_permission,
                                             repo=repo,
                                             permission=desired))
                        modified = True

                # remove teams not desired
                desired_teams = [a['team'] for a in accesses]
                existing_teams = [t.id for t in repo.get_teams()]
                teams_to_remove = set(existing_teams).difference(desired_teams)
                for team_id in teams_to_remove:
                    team = next(filter(lambda t, team_id=team_id: t.id == team_id, self._all_teams))
                    mods.append(self._create_mod(mod_type='repo', func=team.remove_from_repos, repo=repo))
                    modified = True

        return mods, modified

    def get_all_mods(self):
        """Return all the modifications to be performed."""
        mods = []

        team_mods, team_modified = self.get_team_mods()
        repo_mods, repo_modified = self.get_repo_mods()

        mods.extend(team_mods)
        mods.extend(repo_mods)

        return mods, team_modified or repo_modified


def main():
    """Initialize Ansible module."""
    # Parsing argument file
    module = basic.AnsibleModule(
        supports_check_mode=True,
        argument_spec=dict(
            token=dict(required=True, type='str'),
            path=dict(required=False, type='str'),
            config=dict(required=False, type='dict'),
            url=dict(required=False, type='str'),
        ),
    )

    manager = GithubManager(module)
    result = manager.run()

    module.exit_json(**result)


if __name__ == "__main__":
    main()
