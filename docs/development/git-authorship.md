# Git Commit Authorship Guide

## Overview

Kernel Borderlands is occasionally developed from a shared working repository during collaborative development sessions. In these situations, changing the repository's Git configuration (`user.name` and `user.email`) for every contributor is discouraged because it is easy to forget to switch identities, which can result in incorrect commit attribution.

Instead, contributors should specify the commit author explicitly using Git's `--author` option whenever creating or amending commits.

This approach keeps the repository configuration unchanged while ensuring that each commit is attributed to the correct contributor on GitHub.

> **Note**
>
> The `--author` option changes the **Author** field of the commit. The **Committer** field remains the user who executed the commit. This workflow is intended only for collaborative development using a shared working copy.

---

# Creating a New Commit

After completing your changes:

```bash
git add .
```

Create the commit using your author information.

```bash
git commit \
  --author="Your Name <your-email@example.com>" \
  -m "type: concise description"
```

Always include your own name and email address exactly as they are associated with your GitHub account.

---

# Amending the Previous Commit

If the previous commit was created using the wrong author information and has **not yet been pushed**, it can be corrected without creating a new commit.

```bash
git commit \
  --amend \
  --author="Your Name <your-email@example.com>" \
  --no-edit
```

The `--no-edit` flag preserves the existing commit message while updating only the author information.

---

# Verifying Commit Authorship

Before pushing, verify that the commit contains the correct author.

```bash
git log -1 --format=full
```

or

```bash
git show --no-patch
```

Example output:

```text
Author: Kandukoori Teju <...>
Commit: Pardhu Sree Rushi Varma <...>

commit msg ....
```

Ensure that the **Author** field matches your identity before pushing.

---

# Repository Commit Authors (Core Team Specific)

Use the following author information when creating commits from the shared repository.

## PardhuVarma Konduru

GitHub: **PardhuVarma**

```bash
git commit \
  --author="PardhuVarma Konduru <140948604+pardhuvarmax@users.noreply.github.com>" \
  -m "<commit message>"
```

Amend the previous commit:

```bash
git commit \
  --amend \
  --author="PardhuVarma Konduru <140948604+pardhuvarmax@users.noreply.github.com>" \
  --no-edit
```

---

## Kandukoori Teju

GitHub: **Tejaswini4119**

```bash
git commit \
  --author="Kandukoori Teju <k*****tej*******@gmail.com>" \
  -m "<commit message>"
```

Amend the previous commit:

```bash
git commit \
  --amend \
  --author="Kandukoori Teju <k*****tej*******@gmail.com>" \
  --no-edit
```

---

## Karedla Rupa Yeshvitha

GitHub: *(add username if applicable)*

```bash
git commit \
  --author="Karedla Rupa Yeshvitha <karedla*****@gmail.com>" \
  -m "<commit message>"
```

Amend the previous commit:

```bash
git commit \
  --amend \
  --author="Karedla Rupa Yeshvitha <karedla*****@gmail.com>" \
  --no-edit
```

---

## Karthik

GitHub: **Karthik21002**

```bash
git commit \
  --author="Karthik <k****karthik0@gmail.com>" \
  -m "<commit message>"
```

Amend the previous commit:

```bash
git commit \
  --amend \
  --author="Karthik <k****karthik@gmail.com>" \
  --no-edit
```

---

# Updating an Incorrectly Pushed Commit

If a commit with incorrect author information has already been pushed to the remote repository:

1. Correct the commit author using `git commit --amend`.
2. Update the remote history:

```bash
git push --force-with-lease
```

Because this rewrites Git history, it should only be performed after coordinating with other contributors working on the same branch.

---

# Best Practices

* Always specify the commit author using the `--author` option when working from a shared repository.
* Verify commit authorship before pushing changes.
* Do not change the repository's `user.name` or `user.email` configuration for temporary author switching.
* Avoid rewriting shared history unless necessary and coordinated with the team.
* Ensure that the email address used in the `--author` option is associated with your GitHub account so that commits are correctly attributed.

Following this workflow ensures consistent commit attribution while allowing multiple contributors to collaborate safely from the same working repository without repeatedly modifying Git configuration.
