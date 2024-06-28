#!/usr/bin/env python

import os
import sys
import datetime
import json

from github import Github, Auth

GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", None)
if not GITHUB_TOKEN:
    raise ValueError("GITHUB_TOKEN is not set")

full_name = sys.argv[1]
number = int(sys.argv[2])

auth = Auth.Token(GITHUB_TOKEN)
g = Github(auth=auth)

repo = g.get_repo(full_name)
issue = repo.get_issue(number)

query_date = datetime.datetime.now(datetime.UTC) - datetime.timedelta(hours=1)

unique_comment_authors = set()
unique_reaction_authors = set()
mentions_count = 0

unique_comment_authors = {
    comment.user.login for comment in issue.get_comments(query_date) if comment.user
}

unique_reaction_authors = {
    reaction.user.login
    for reaction in issue.get_reactions()
    if reaction.user and reaction.created_at > query_date
}

for timeline_event in issue.get_timeline():
    if (
        timeline_event.event in ["cross-referenced", "referenced"]
        and timeline_event.created_at > query_date
    ):
        mentions_count += 1

data = {
    "unique_comments": len(unique_comment_authors),
    "unique_reactions": len(unique_reaction_authors),
    "mentions": mentions_count,
}

with open("issue_data.json", "w") as f:
    json.dump(data, f)
