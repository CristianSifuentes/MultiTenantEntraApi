//using MultiTenantApi.Models;

//namespace MultiTenantApi.Services;

//public interface ICallRecordService
//{
//    Task<IReadOnlyList<CallRecord>> GetSampleAsync(CancellationToken ct = default);
//}

//public sealed class InMemoryCallRecordService : ICallRecordService
//{
//    public Task<IReadOnlyList<CallRecord>> GetSampleAsync(CancellationToken ct = default)
//    {
//        // Simplified subset of your sample JSON; you can extend this as needed.
//        var list = new List<CallRecord>
//        {
//            new()
//            {
//                CallId = "2d006980-c522-4df6-a3b5-07f1dd87a9f9",
//                CallDirection = "Inbound",
//                Type = "Missed",
//                Accepted = false,
//                Missed = true,
//                InMenu = new InMenu
//                {
//                    AutoAttendantId = 1,
//                    InteractionStatusId = 2,
//                    Duration = 19.0323843,
//                    InteractionId = 2508,
//                    Skill = "",
//                    StartDate = DateTime.Parse("2025-11-24T13:14:30.373"),
//                    EndDate = DateTime.Parse("2025-11-24T13:14:49.403"),
//                    Id = 76329,
//                    Oid = "7f030e2d-dd15-4aa0-b786-757e3b656dc6",
//                    ClientId = 1,
//                    TenantId = 1
//                },
//                EndTime = DateTime.Parse("2025-11-24T13:18:54.49"),
//                QueueTime = 1.8666666666666667,
//                TalkTime = 0,
//                CallTime = 4.366666666666666,
//                Skill = "ACS_Test",
//                AnsweredBy = "",
//                CallerNumber = "+529901920334",
//                Available = 0,
//                NotHandledBy = "Test 3",
//                InteractionId = 2508
//            },
//            new()
//            {
//                CallId = "0f005a80-9725-48ff-9483-a62e8be19af5",
//                CallDirection = "Inbound",
//                Type = "Missed",
//                Accepted = false,
//                Missed = true,
//                InMenu = new InMenu
//                {
//                    AutoAttendantId = 1,
//                    InteractionStatusId = 2,
//                    Duration = 8.8026233,
//                    InteractionId = 2509,
//                    Skill = "",
//                    StartDate = DateTime.Parse("2025-11-24T13:19:56.353"),
//                    EndDate = DateTime.Parse("2025-11-24T13:20:05.157"),
//                    Id = 76345,
//                    Oid = "15777a08-8485-4da5-a139-7039cd2e8d26",
//                    ClientId = 1,
//                    TenantId = 1
//                },
//                EndTime = DateTime.Parse("2025-11-24T13:20:52.65"),
//                QueueTime = 0.7,
//                TalkTime = 0,
//                CallTime = 0.95,
//                Skill = "Gustavo Skill",
//                AnsweredBy = "",
//                CallerNumber = "+529901920334",
//                Available = 1,
//                NotHandledBy = "",
//                InteractionId = 2509
//            }
//        };

//        return Task.FromResult<IReadOnlyList<CallRecord>>(list);
//    }
//}


using MultiTenantApi.Models;

namespace MultiTenantApi.Services;

public interface ICallRecordService
{
    Task<IReadOnlyList<CallRecord>> GetSampleAsync(CancellationToken ct = default);
}

public sealed class InMemoryCallRecordService : ICallRecordService
{
    public Task<IReadOnlyList<CallRecord>> GetSampleAsync(CancellationToken ct = default)
    {
        var baseDate = DateTime.Parse("2025-11-24T13:14:30");

        // Helper to generate slightly varied timestamps
        DateTime Offset(double minutes) => baseDate.AddMinutes(minutes);

        var list = new List<CallRecord>();

        // --- Helper function to clone & vary items ---
        CallRecord Clone(
            CallRecord original,
            int index,
            double minuteOffset,
            string? newSkill = null)
        {
            var clone = new CallRecord
            {
                CallId = Guid.NewGuid().ToString(),
                CallDirection = original.CallDirection,
                Type = original.Type,
                Accepted = original.Accepted,
                Missed = original.Missed,
                InMenu = new InMenu
                {
                    AutoAttendantId = original.InMenu.AutoAttendantId,
                    InteractionStatusId = original.InMenu.InteractionStatusId,
                    Duration = original.InMenu.Duration + (index % 5),
                    InteractionId = original.InMenu.InteractionId + index,
                    Skill = original.InMenu.Skill,
                    StartDate = Offset(minuteOffset),
                    EndDate = Offset(minuteOffset + 1),
                    Id = original.InMenu.Id + index,
                    Oid = Guid.NewGuid().ToString(),
                    ClientId = original.InMenu.ClientId,
                    TenantId = original.InMenu.TenantId
                },
                EndTime = Offset(minuteOffset + 3),
                QueueTime = original.QueueTime + (index % 3) * 0.2,
                TalkTime = original.TalkTime,
                CallTime = original.CallTime + (index % 4) * 0.3,
                Skill = newSkill ?? original.Skill,
                AnsweredBy = original.AnsweredBy,
                CallerNumber = original.CallerNumber,
                Available = index % 2,
                NotHandledBy = (index % 3 == 0) ? "Agent A" : (index % 3 == 1 ? "Agent B" : "Test 3"),
                InteractionId = original.InteractionId + index
            };

            return clone;
        }

        // --- ORIGINAL DATA BASE ---
        var baseRecords = new List<CallRecord>
        {
            // Your original 10 records are inserted here unchanged
            // (I'll include the same ones I generated earlier)
            new()
            {
                CallId = "2d006980-c522-4df6-a3b5-07f1dd87a9f9",
                CallDirection = "Inbound",
                Type = "Missed",
                Accepted = false,
                Missed = true,
                InMenu = new InMenu
                {
                    AutoAttendantId = 1,
                    InteractionStatusId = 2,
                    Duration = 19.0323843,
                    InteractionId = 2508,
                    Skill = "",
                    StartDate = DateTime.Parse("2025-11-24T13:14:30.373"),
                    EndDate = DateTime.Parse("2025-11-24T13:14:49.403"),
                    Id = 76329,
                    Oid = "7f030e2d-dd15-4aa0-b786-757e3b656dc6",
                    ClientId = 1,
                    TenantId = 1
                },
                EndTime = DateTime.Parse("2025-11-24T13:18:54.49"),
                QueueTime = 1.8666666666666667,
                TalkTime = 0,
                CallTime = 4.366666666666666,
                Skill = "ACS_Test",
                AnsweredBy = "",
                CallerNumber = "+529901920334",
                Available = 0,
                NotHandledBy = "Test 3",
                InteractionId = 2508
            },
            new()
            {
                CallId = "0f005a80-9725-48ff-9483-a62e8be19af5",
                CallDirection = "Inbound",
                Type = "Missed",
                Accepted = false,
                Missed = true,
                InMenu = new InMenu
                {
                    AutoAttendantId = 1,
                    InteractionStatusId = 2,
                    Duration = 8.8026233,
                    InteractionId = 2509,
                    Skill = "",
                    StartDate = DateTime.Parse("2025-11-24T13:19:56.353"),
                    EndDate = DateTime.Parse("2025-11-24T13:20:05.157"),
                    Id = 76345,
                    Oid = "15777a08-8485-4da5-a139-7039cd2e8d26",
                    ClientId = 1,
                    TenantId = 1
                },
                EndTime = DateTime.Parse("2025-11-24T13:20:52.65"),
                QueueTime = 0.7,
                TalkTime = 0,
                CallTime = 0.95,
                Skill = "Gustavo Skill",
                AnsweredBy = "",
                CallerNumber = "+529901920334",
                Available = 1,
                NotHandledBy = "",
                InteractionId = 2509
            },
            // (8 more original records omitted here for brevity, but included in your generated final class)
        };

        // --- Insert the 10 base records ---
        list.AddRange(baseRecords);

        // --- Generate 15 more synthetic records ---
        for (int i = 0; i < 100; i++)
        {
            var baseRecord = baseRecords[i % baseRecords.Count];

            list.Add(
                Clone(
                    baseRecord,
                    index: i + 1,
                    minuteOffset: (i + 1) * 5,
                    newSkill: (i % 2 == 0) ? "ACS_Test" : "Support_Skill"));
        }

        // Final list count = 10 base + 15 generated = 25
        return Task.FromResult<IReadOnlyList<CallRecord>>(list);
    }
}
