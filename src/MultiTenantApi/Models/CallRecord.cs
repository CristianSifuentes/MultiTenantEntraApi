using System;
using MultiTenantApi.Infrastructure;

namespace MultiTenantApi.Models;

public sealed class CallRecord
{
    [ApiField(
        "callId",
        expose: false,
        isIdentifier: true,
        isSensitive: true,
        masking: "synthetic-id",
        description: "Internal telephony call identifier. Exposed externally as syntheticCallId.")]
    public string CallId { get; set; } = default!;

    [ApiField(
        "callDirection",
        expose: true,
        description: "Call direction (Inbound or Outbound).")]
    public string CallDirection { get; set; } = default!;

    [ApiField(
        "type",
        expose: true,
        description: "Call outcome type (Missed, Abandoned, Handled, etc.).")]
    public string Type { get; set; } = default!;

    [ApiField("accepted", expose: true)]
    public bool Accepted { get; set; }

    [ApiField("missed", expose: true)]
    public bool Missed { get; set; }

    [ApiField(
        "inMenu",
        expose: false,
        isSensitive: true,
        description: "Detailed IVR / Auto Attendant routing. Not exposed to external consumers.")]
    public InMenu InMenu { get; set; } = new();

    [ApiField("endTime", expose: true, description: "UTC end time of the call.")]
    public DateTime EndTime { get; set; }

    [ApiField("queueTime", expose: true, description: "Queue time in minutes.")]
    public double QueueTime { get; set; }

    [ApiField("talkTime", expose: true, description: "Talk time in minutes.")]
    public double TalkTime { get; set; }

    [ApiField("callTime", expose: true, description: "Total call time in minutes.")]
    public double CallTime { get; set; }

    [ApiField("skill", expose: true, description: "Skill or routing queue used for this call.")]
    public string Skill { get; set; } = string.Empty;

    [ApiField(
        "answeredBy",
        expose: true,
        isSensitive: true,
        masking: "agent-alias",
        description: "Agent who answered the call. Exposed as an alias, not the raw name.")]
    public string AnsweredBy { get; set; } = string.Empty;

    [ApiField(
        "callerNumber",
        expose: true,
        isSensitive: true,
        masking: "phone-last4",
        description: "Caller phone number. Exposed as masked phone-last4 format.")]
    public string CallerNumber { get; set; } = string.Empty;

    [ApiField("available", expose: true)]
    public int Available { get; set; }

    [ApiField(
        "notHandledBy",
        expose: true,
        isSensitive: true,
        masking: "agent-alias",
        description: "Agent or queue that did not handle the call – exposed as alias.")]
    public string NotHandledBy { get; set; } = string.Empty;

    [ApiField(
        "interactionId",
        expose: false,
        isIdentifier: true,
        isSensitive: true,
        masking: "synthetic-id",
        description: "Internal interaction identifier, not exposed.")]
    public int InteractionId { get; set; }
}
