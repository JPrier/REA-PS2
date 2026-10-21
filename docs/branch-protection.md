# GitHub branch protection setup

Workflow files cannot enable branch protection. A repository administrator must create a ruleset for the default branch and require the following status check by its exact name:

```text
REA-PS2 Required
```

Enable required pull requests before merging, require the branch to be up to date, dismiss stale approvals when new commits are pushed, and block force pushes and branch deletion. Do not grant bypass to ordinary users or automation tokens. Keep the `required` workflow job dependent on every mandatory check; a missing, failed, cancelled, or skipped dependency must leave the aggregate gate failed.

No GitHub API credentials or repository administration permissions were available during initial implementation, so these settings have not been applied or verified remotely.
