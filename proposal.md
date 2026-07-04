# Project Proposal 1

## I. Administrative Details

**Project Title:** TraceGuard: A Supervisor for Safe Tool-Using Agents

**Team Members:**  
[Student 1]  
[Student 2]  
[Student 3]

## II. Problem Statement and Motivation

LLM agents are increasingly used not only to answer questions, but also to act: they search, read files, call APIs, execute code, write reports, and interact with external systems. This creates a safety and reliability problem. If the agent receives adversarial instructions from the user, a retrieved document, or a tool output, it may perform unsafe actions such as leaking private information, accessing irrelevant files, executing unintended commands, or calling tools with manipulated arguments.

Current search and retrieval approaches usually focus on finding relevant information, but they do not control what the agent does after receiving that information. Standard RAG can retrieve useful evidence, but it does not reliably distinguish between factual content and malicious instructions embedded inside that content. Similarly, many tool-using agents rely on the LLM itself to decide whether a tool call is appropriate, which is unreliable when tools have side effects.

The gap addressed by this project is the lack of a lightweight, inspectable supervision layer between the LLM agent and its tools. The goal is to make tool-using agents safer by validating, monitoring, and, when necessary, blocking unsafe tool calls before execution.

## III. Proposed Methodology

We will build a ReAct-style tool-using agent that solves multi-step information-processing tasks using several tools, such as document search, file reading, calculator, report writing, and a restricted command-execution tool. The tools will run in a controlled sandbox with typed schemas and execution logs.

A separate supervisor module will inspect every proposed tool call before it is executed. The supervisor will receive the user task, recent agent observations, the proposed tool name, tool arguments, and a safety policy. It will return one of three decisions: allow, block, or escalate.

The architecture will include:

1. A task agent that plans and proposes tool calls.
2. A typed tool runtime that validates tool arguments and executes approved calls.
3. A safety supervisor combining rule-based checks and LLM-based judgment.
4. A benchmark of benign tasks and adversarial tasks.
5. A trace logger showing the agent’s reasoning steps, proposed actions, supervisor decisions, and final result.

We will evaluate multiple configurations: no supervisor, rule-only supervisor, LLM-only supervisor, and hybrid rule + LLM supervisor.

## IV. Evaluation Plan

Success will be measured using both safety and task-performance metrics:

- Attack success rate: how often adversarial prompts lead to unsafe tool execution.
- Unsafe-call blocking rate: how often dangerous tool calls are correctly blocked.
- Benign task success rate: whether normal tasks are still completed.
- False positive rate: how often safe tool calls are incorrectly blocked.
- False negative rate: how often unsafe tool calls are allowed.
- Tool-call accuracy: whether the agent chooses appropriate tools and arguments.
- Latency and token overhead added by the supervisor.

The main objective is to reduce unsafe tool execution while preserving useful agent behavior on normal tasks.

## V. Expected Deliverables

The final output will include a working supervised agent runtime, a small benchmark of benign and adversarial tool-use tasks, an evaluation report with ablation results, execution traces, and a short demo showing unsafe tool calls being detected and blocked before execution.