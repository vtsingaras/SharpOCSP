using System;
using System.Linq;
using log4net;
using log4net.Layout;

namespace log4netExtensions
{
	public static class ILogExtensions
	{
		public static void Trace(this ILog log, string message, Exception exception)
		{
			log.Logger.Log(System.Reflection.MethodBase.GetCurrentMethod().DeclaringType, 
				log4net.Core.Level.Trace, message, exception);
		}

		public static void Trace(this ILog log, string message)
		{
			log.Trace(message, null);
		}

		public static void Verbose(this ILog log, string message, Exception exception)
		{
			log.Logger.Log(System.Reflection.MethodBase.GetCurrentMethod().DeclaringType, 
				log4net.Core.Level.Verbose, message, exception);
		}

		public static void Verbose(this ILog log, string message)
		{
			log.Verbose(message, null);
		}
		public static void Always(this ILog log, string message, Exception exception)
		{
			log.Logger.Log(System.Reflection.MethodBase.GetCurrentMethod().DeclaringType, 
				log4net.Core.Level.Off, message, exception);
		}

		public static void Always(this ILog log, string message)
		{
			log.Always(message, null);
		}
	}
}

