using System;
using System.Threading;
using Mono.Unix;
using Mono.Unix.Native;

namespace SharpOCSP
{
	public class SignalHandler : IDisposable
	{
		public delegate void SignaledDelegate();
		private static Thread signaling_thread;
		private SignaledDelegate _sigusr1_delegate = null;
		private SignaledDelegate _sigusr2_delegate = null;

		private void signalHandlerThread()
		{
			UnixSignal[] signals = new UnixSignal [] {
				new UnixSignal (Signum.SIGUSR1),
				new UnixSignal (Signum.SIGUSR2),
			};

			while (true) {
				int index = UnixSignal.WaitAny (signals, -1);
				Signum signal = signals [index].Signum;
				signalHandler(signal);
			};
		}

		private void signalHandler(Signum signal)
		{
			switch (signal)
			{
			case Signum.SIGUSR1:
				_sigusr1_delegate();
				break;
			case Signum.SIGUSR2:
				_sigusr2_delegate();
				break;
			default:
				break;
			}
		}
		public SignalHandler (SignaledDelegate sigusr1_delegate, SignaledDelegate sigusr2_delegate)
		{
			_sigusr1_delegate = sigusr1_delegate;
			_sigusr2_delegate = sigusr2_delegate;
			signaling_thread = new Thread(new ThreadStart(signalHandlerThread));
			signaling_thread.Start();
		}
		public void Dispose()
		{
			signaling_thread.Abort ();
		}
	}
}

