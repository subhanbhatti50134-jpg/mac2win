using System;
using System.Threading;
using System.Windows;
using System.Windows.Threading;
using Xunit;

namespace Mac2WinReceiver.App.Tests;

/// <summary>Runs a test body on a dedicated STA thread (required for WPF).
/// Test bodies must <b>never await</b> — they fire tasks and pump with Dispatcher.PushFrame.</summary>
public static class StaRunner
{
    public static void Run(Action body, TimeSpan? timeout = null)
    {
        var t = new Thread(() =>
        {
            // WPF requires an Application instance on the STA thread
            _ = new Application();
            SynchronizationContext.SetSynchronizationContext(
                new DispatcherSynchronizationContext(Dispatcher.CurrentDispatcher));
            body();
        })
        { IsBackground = true, Name = "STA test thread" };
        t.SetApartmentState(ApartmentState.STA);
        t.Start();
        t.Join(timeout ?? TimeSpan.FromSeconds(30));
        if (t.IsAlive) throw new TimeoutException("STA test body did not complete in time");
    }

    /// <summary>Pumps the WPF dispatcher until a condition becomes true.</summary>
    public static class Pump
    {
        /// <summary>Pumps until <paramref name="condition"/> is true, or timeout.</summary>
        public static bool Until(Func<bool> condition, TimeSpan? timeout = null)
        {
            var dispatcher = Dispatcher.CurrentDispatcher;
            var timer = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(50) };
            var done = false;
            timer.Tick += (_, _) =>
            {
                if (condition())
                {
                    done = true;
                    timer.Stop();
                    dispatcher.InvokeShutdown();
                }
            };
            timer.Start();
            Dispatcher.Run();
            return done;
        }

        /// <summary>Pumps for a fixed duration, allowing UI updates and continuations to run.</summary>
        public static void For(TimeSpan duration)
        {
            var dispatcher = Dispatcher.CurrentDispatcher;
            var timer = new DispatcherTimer { Interval = duration };
            timer.Tick += (_, _) => dispatcher.InvokeShutdown();
            timer.Start();
            Dispatcher.Run();
        }
    }
}
