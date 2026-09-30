# The key we ask for, and what it cannot do

Handing an API key to a third party deserves suspicion. This page is what we would want to
read before doing it ourselves: exactly what the key can reach, exactly what it cannot, and
how to take it back.

Short version: **one `Project Read Only` API key, and nothing else.** No database user, no
agent, no software installed anywhere. It cannot read your data and it cannot change anything.

## Why an API key and not a database user

These are two different things and the difference matters.

A **database user** connects to MongoDB itself. That is what an application uses, and it is
the credential that can read collections.

An **API key** talks to the Atlas control plane — the same thing the Atlas web console talks
to. It can ask about clusters, their configuration and their diagnostics. It has no way to
open a connection to a database, because that is not what the API does.

We ask for the second kind. Nothing we run ever connects to your database.

## What `Project Read Only` grants

It is the lowest role Atlas offers. It can:

- list the clusters in the project, their tier, version and region
- request a diagnostic bundle (FTDC) and download it

That is the entire basis of the service.

It **cannot**:

- read, write or delete a single document
- connect to any database
- create, resize, pause or delete a cluster
- change any setting, including autoscaling
- create users, roles, or other API keys
- see billing, or anything in other projects

The role is enforced by Atlas, not by us. Even if our software tried to do any of the above,
Atlas would refuse it. You are relying on MongoDB's permission system rather than on our
good behaviour — which is the right way round.

A concrete consequence, and a slightly awkward one for us: when a cluster has autoscaling on,
we cannot turn it off. We can only tell you it is on and ask you to do it.

## What is actually in an FTDC bundle

FTDC is what MongoDB support asks for on any performance ticket. It is a numeric time series:
about 5,700 counters and gauges, once per second. Ticket pools, cache bytes, operation
counters, queue depths, memory, disk.

**It contains no documents and no queries.** By construction: the format holds numbers, and
the only text in it is metadata — hostnames, the MongoDB version, the command line mongod was
started with.

We checked rather than assumed. A real three-node bundle from a production-shaped cluster
contains 38 distinct strings in total, and not one of them is a database name, a collection
name, a field name or a query.

## What we ask you NOT to give us

**We do not ask for this and we do not use it.** It is here because other monitoring tools do
ask for it, and knowing what it grants is useful whether or not you ever use this service.

The usual role for monitoring MongoDB is `clusterMonitor`. It reads as a metrics role. From
MongoDB's own source, `src/mongo/db/auth/builtin_roles.yml`:

```yaml
clusterMonitor:
  adminOnly: true
  roles:
    - role: read
      db: config
    - role: read
      db: local
```

`read` on `local` includes `local.oplog.rs` — the oplog, which holds the full content of every
recent write. An account with `clusterMonitor` can page back through everything your
application wrote for as long as the oplog window holds. The documents themselves, not
statistics about them.

We do not ask for it, we do not want it, and if a monitoring vendor asks you for it, it is
worth asking them why.

## Creating the key

1. Atlas → **Access Manager** → the project → **API Keys** → **Create API Key**
2. Description: something you will recognise later, e.g. `big-hole-collector`
3. Project Permissions: **`Project Read Only`** and nothing else
4. Copy the **public key** and the **private key**

Atlas shows the private key **once**. If you lose it, delete that key and make another —
there is no way to display it again.

## Restricting it further

Two things worth doing, neither of which we can do for you.

**Tie it to our IP.** Access Manager → your key → **API Access List**. Adding only the address
we give you means the key is useless from anywhere else, even if it leaks. If you already have
`0.0.0.0/0` on that list, it accepts calls from anywhere — worth removing regardless of
whether you use this service.

**Give it its own project.** If you want a hard boundary, an Atlas project containing only the
clusters you want watched means the key cannot enumerate anything else, by construction.

## Taking it back

Access Manager → API Keys → **Delete**. It stops working immediately.

Collection stops at the next run, with no side effects on your cluster: nothing was installed,
no agent runs anywhere, and no configuration of yours was ever modified. What we already
captured stays in your account until you ask us to delete it, and we delete it on request
without asking why.

## What this costs your cluster

Building a bundle is work Atlas does on its own infrastructure, not on your nodes. FTDC is
already being written continuously by every mongod whether or not anyone collects it — we are
asking Atlas for a copy of a file that already exists.

We request one every hour. There is no agent, nothing to install, and no continuous connection
to your cluster.
