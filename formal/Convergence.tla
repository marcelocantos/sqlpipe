---- MODULE Convergence ----
(*******************************************************************************
 * Models the sqlpipe convergence loop: Master (data owner) and Replica
 * communicate over a lossy, unordered channel.
 *
 * Abstraction: rows are integers, fingerprint = data set, patchset = full data.
 *
 * The channel is modelled as two flags: probe_pending (replica→master) and
 * response_pending (master→replica). Either can be "delivered" or "lost."
 * This avoids TLA+ fairness complications with set-based channels.
 *
 * Properties:
 *   Safety      — replica_data ⊆ master_data.
 *   Convergence — if master stops writing, replica eventually matches.
 ******************************************************************************)

EXTENDS Integers, FiniteSets, Sequences

CONSTANTS
    MaxRows,
    MaxQueueLen

VARIABLES
    m_data,    \* Master's row set
    m_seq,     \* Master's sequence number
    queue,     \* Changeset queue: sequence of <<seq, data>>
    r_data,    \* Replica's row set
    r_seq,     \* Replica's last applied seq
    probe,     \* "Probe" in flight: NONE | [seq, hash]
    response,  \* "Response" in flight: NONE | [type, seq, data]
    stopped    \* Master has stopped writing

vars == <<m_data, m_seq, queue, r_data, r_seq, probe, response, stopped>>

NONE == [type |-> "none"]

Init ==
    /\ m_data = {}
    /\ m_seq = 0
    /\ queue = <<>>
    /\ r_data = {}
    /\ r_seq = 0
    /\ probe = NONE
    /\ response = NONE
    /\ stopped = FALSE

----

\* Master writes a new row.
Write ==
    /\ ~stopped
    /\ m_seq < MaxRows
    /\ LET r == m_seq + 1
           d == m_data \union {r}
           q == IF Len(queue) >= MaxQueueLen
                THEN Append(Tail(queue), <<r, d>>)
                ELSE Append(queue, <<r, d>>)
       IN /\ m_data' = d
          /\ m_seq' = r
          /\ queue' = q
          /\ UNCHANGED <<r_data, r_seq, probe, response, stopped>>

\* Master stops writing.
Stop ==
    /\ ~stopped
    /\ stopped' = TRUE
    /\ UNCHANGED <<m_data, m_seq, queue, r_data, r_seq, probe, response>>

\* Replica initiates convergence (overwrites any pending probe).
Converge ==
    /\ probe' = [type |-> "probe", seq |-> r_seq, hash |-> r_data]
    /\ UNCHANGED <<m_data, m_seq, queue, r_data, r_seq, response, stopped>>

\* Master receives probe, produces response (overwrites any pending response).
MasterRecv ==
    /\ probe.type = "probe"
    /\ probe' = NONE
    /\ IF probe.seq > 0 /\ probe.seq < m_seq
          /\ Len(queue) > 0
          /\ queue[1][1] <= probe.seq + 1
       THEN \* Queue replay: find the first changeset after probe.seq.
            LET idx == CHOOSE i \in 1..Len(queue) : queue[i][1] > probe.seq
                       /\ (\A j \in 1..Len(queue) : queue[j][1] > probe.seq => j >= i)
            IN response' = [type |-> "changeset", seq |-> queue[idx][1], data |-> queue[idx][2]]
       ELSE IF probe.hash # m_data
       THEN response' = [type |-> "patch", seq |-> m_seq, data |-> m_data]
       ELSE response' = NONE  \* Already in sync.
    /\ UNCHANGED <<m_data, m_seq, queue, r_data, r_seq, stopped>>

\* Replica receives response.
ReplicaRecv ==
    /\ response.type \in {"patch", "changeset"}
    /\ IF response.type = "patch"
       THEN /\ r_data' = response.data
            /\ r_seq' = response.seq
       ELSE IF response.seq = r_seq + 1
       THEN /\ r_data' = response.data
            /\ r_seq' = response.seq
       ELSE UNCHANGED <<r_data, r_seq>>  \* Wrong seq, drop.
    /\ response' = NONE
    /\ UNCHANGED <<m_data, m_seq, queue, probe, stopped>>

\* Probe is lost.
LoseProbe ==
    /\ probe.type = "probe"
    /\ probe' = NONE
    /\ UNCHANGED <<m_data, m_seq, queue, r_data, r_seq, response, stopped>>

\* Response is lost.
LoseResponse ==
    /\ response.type \in {"patch", "changeset"}
    /\ response' = NONE
    /\ UNCHANGED <<m_data, m_seq, queue, r_data, r_seq, probe, stopped>>

----

Next ==
    \/ Write
    \/ Stop
    \/ Converge
    \/ MasterRecv
    \/ ReplicaRecv
    \/ LoseProbe
    \/ LoseResponse

\* Fairness:
\*   WF on Converge: replica keeps probing.
\*   WF on MasterRecv: master processes probes.
\*   SF on ReplicaRecv: if a response is available, replica eventually gets it.
\*   No fairness on Write, Stop, LoseProbe, LoseResponse.
Spec == Init /\ [][Next]_vars
        /\ WF_vars(Converge)
        /\ SF_vars(MasterRecv)
        /\ SF_vars(ReplicaRecv)

----

Safety == r_data \subseteq m_data

Convergence == stopped ~> (r_data = m_data)

====
