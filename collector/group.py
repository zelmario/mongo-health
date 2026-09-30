"""Collapse the same symptom across nodes into one thing to report.

An incident does not respect node boundaries. Load a replica set hard enough and all three
members run short of memory, all three take long checkpoints, and the primary saturates its
ticket pool — which the rules correctly report as six findings, and which a reader correctly
experiences as one bad afternoon.

The email that came out of the real cluster said "15 findings" in its subject. Nobody opens
that. It is not that the findings were wrong; it is that counting them is the wrong unit.

So: group by rule, keep every node's evidence, and report "three nodes ran out of memory" as
one line rather than three. The grouping is deliberately conservative — same rule, overlapping
in time — because merging two genuinely separate episodes would hide one of them, and hiding a
finding is worse than repeating one.
"""
from __future__ import annotations

from dataclasses import dataclass, field

# Two findings of the same rule count as one incident when their windows are within this of
# each other. A replica set reacts together but not to the millisecond: a node starts
# struggling minutes before its peers, and an incident whose members are ten minutes apart is
# still one incident.
TOGETHER_MS = 10 * 60 * 1000


@dataclass
class Group:
    rule: str
    title: str
    severity: str
    members: list[dict] = field(default_factory=list)

    @property
    def nodes(self) -> list[str]:
        seen, out = set(), []
        for f in self.members:
            short = f["node"].split(".")[0]
            if short not in seen:
                seen.add(short)
                out.append(short)
        return sorted(out)

    @property
    def from_ms(self) -> int:
        return min(f["fromMs"] for f in self.members)

    @property
    def to_ms(self) -> int:
        return max(f["toMs"] for f in self.members)

    @property
    def worst(self) -> dict:
        """The member to show. Longest time in state -- the one worth looking at first."""
        return max(self.members, key=lambda f: f.get("secondsInState", 0))

    @property
    def seconds_in_state(self) -> int:
        """The worst member's duration, NOT the sum.

        Adding them would claim an incident lasted three times longer than it did, because the
        nodes were struggling at the same time rather than one after another.
        """
        return self.worst.get("secondsInState", 0)

    def headline(self, brief: bool = False) -> str:
        """One sentence naming the scope, which is what the count was trying to convey.

        `brief` is for subject lines. Atlas hostnames run to forty characters, so naming even
        two of them buries the part that decides whether the mail gets opened — which is what
        happened, not where. The body has room for the full names.
        """
        # Some findings belong to the replica set rather than to a node. An election is the
        # clearest: every member lives through the same one, and the member that happened to
        # report it first is not where anybody should go looking. Naming it reads as an
        # accusation of an innocent host.
        if self.rule in CLUSTER_WIDE:
            return self.title

        n = len(self.nodes)
        if n == 1:
            return f"{self.title} on {self.nodes[0]}"
        if n == 2 and not brief:
            return f"{self.title} on {self.nodes[0]} and {self.nodes[1]}"
        return f"{self.title} on {n} nodes"


# Rules whose subject is the set, not a member of it.
# Sizing advice is about the tier, and every member is the same tier.
# Replication lag is measured across the members, so every node reports the same
# number for the same event. Naming one of them would blame a witness.
CLUSTER_WIDE = frozenset({"election-held", "oversized-cluster", "replication-lag"})


def group(findings: list[dict]) -> list[Group]:
    """Same rule, overlapping windows, one group. Order: worst first."""
    groups: list[Group] = []

    for f in sorted(findings, key=lambda x: (x["rule"], x["fromMs"])):
        target = None
        for g in groups:
            if g.rule != f["rule"]:
                continue
            # Overlapping, or close enough that they are the same episode seen from two nodes.
            if f["fromMs"] <= g.to_ms + TOGETHER_MS and f["toMs"] >= g.from_ms - TOGETHER_MS:
                target = g
                break
        if target is None:
            target = Group(rule=f["rule"], title=f["title"], severity=f["severity"])
            groups.append(target)
        target.members.append(f)
        # A group is as severe as its worst member: two warnings and one critical is a
        # critical, because that is the one that decides whether this interrupts anybody.
        order = {"critical": 0, "warning": 1, "info": 2}
        if order.get(f["severity"], 3) < order.get(target.severity, 3):
            target.severity = f["severity"]

    return sorted(groups, key=lambda g: (
        {"critical": 0, "warning": 1, "info": 2}.get(g.severity, 3),
        -g.seconds_in_state,
    ))


def name_nodes(nodes: list[str]) -> str:
    """The nodes of a finding, written so a reader can tell them apart at a glance.

    mongod reports itself as `host` when it listens on 27017 and as `host:port` otherwise, so a
    replica set sharing one machine comes out as "dbhost, dbhost:27018, dbhost:27019" —
    which reads as three unrelated things, and buries the fact that matters: they are one
    machine. Collapsed to "dbhost (27017, 27018, 27019)" it says so, and the missing port is
    supplied rather than guessed, because 27017 is the only one mongod omits.

    Separate hosts are left alone: on Atlas the names differ from the first character and there
    is nothing to collapse.
    """
    if not nodes:
        return ""

    partes = [n.rsplit(":", 1) if ":" in n else [n, "27017"] for n in nodes]
    hosts = {h for h, _ in partes}
    if len(hosts) > 1 or len(partes) < 2:
        return ", ".join(nodes)

    puertos = sorted({p for _, p in partes}, key=lambda x: int(x) if x.isdigit() else 0)
    return f"{partes[0][0]} ({', '.join(puertos)})"


def subject_for(cluster_id: str, incidents: list) -> str:
    """What the subject line should say.

    One gets named outright, because a specific subject is what gets opened. Several get
    counted -- and the count is of INCIDENTS, not of findings or of rules. A subject saying
    "and 38 more" for a day that a reader would describe as five bad moments overstates the
    problem and, worse, trains them to stop opening the mail.
    """
    if len(incidents) == 1:
        # One moment: its own headline says everything, signals included.
        return f"[{cluster_id}] {incidents[0].headline(brief=True)}"

    # Several: name the single worst PROBLEM, not the worst moment. A moment's headline
    # already ends in "and 5 other signals", and appending "and 20 more" to that gives a
    # subject with two chained counts of different things -- in the one line somebody uses to
    # decide whether to open it.
    worst = incidents[0].groups[0]
    return f"[{cluster_id}] {worst.headline(brief=True)}, and {len(incidents) - 1} more"


# How close two groups have to be to belong to the same moment. Fifteen minutes: an incident
# does not announce itself with one symptom, it announces itself with five within a few
# minutes of each other, and a reader wants those on one card rather than scattered across a
# list sorted by severity.
SAME_MOMENT_MS = 15 * 60_000


@dataclass
class Moment:
    """Everything that went wrong at roughly the same time.

    The layer above `Group`. A group answers "which rule fired, on which nodes"; a moment
    answers "what happened at 16:38", which is the question somebody opening the report
    actually has. On a real capture the difference was 37 cards, sorted by severity, with the
    ticket saturation of one afternoon sitting three rows away from the checkpoints that
    caused it -- against 9 moments, each one an event with its symptoms underneath.
    """

    groups: list["Group"] = field(default_factory=list)

    @property
    def from_ms(self) -> int:
        return min(g.from_ms for g in self.groups)

    @property
    def to_ms(self) -> int:
        return max(g.to_ms for g in self.groups)

    @property
    def severity(self) -> str:
        order = {"critical": 0, "warning": 1, "info": 2}
        return min((g.severity for g in self.groups), key=lambda s: order.get(s, 3))

    @property
    def nodes(self) -> list[str]:
        seen, out = set(), []
        for g in self.groups:
            for n in g.nodes:
                if n not in seen:
                    seen.add(n)
                    out.append(n)
        return out

    def headline(self, brief: bool = False) -> str:
        """The worst thing that happened, and how much else came with it.

        Naming the worst rather than counting everything: "the ticket pool saturated" is what
        somebody remembers, and "and 4 other signals" tells them there is more without making
        them read a list to find out what it was about.

        `brief` is for subject lines, and drops the node names for the same reason `Group` does.
        """
        worst = self.groups[0]
        rest = len(self.groups) - 1
        if rest == 0:
            return worst.headline(brief=brief)
        return f"{worst.headline(brief=brief)}, and {rest} other signal{'s' if rest != 1 else ''}"


def moments(groups: list[Group]) -> list[Moment]:
    """Group the groups by when they happened. Worst first, then most recent."""
    if not groups:
        return []

    order = {"critical": 0, "warning": 1, "info": 2}
    out: list[Moment] = []
    for g in sorted(groups, key=lambda x: x.from_ms):
        placed = None
        for m in out:
            # Matched on when things STARTED, not on whether they overlap. One finding that
            # runs for a day overlaps everything else in it, and chaining on overlap collapsed
            # a whole capture into a single "moment" containing 37 signals. What makes two
            # things the same event is that they began together.
            if abs(g.from_ms - m.from_ms) <= SAME_MOMENT_MS:
                placed = m
                break
        if placed is None:
            placed = Moment()
            out.append(placed)
        placed.groups.append(g)

    # Inside a moment, worst first: that is what the headline names and what a reader should
    # see before the symptoms that came with it.
    for m in out:
        m.groups.sort(key=lambda g: (order.get(g.severity, 3), -g.seconds_in_state))

    return sorted(out, key=lambda m: (order.get(m.severity, 3), -m.to_ms))
