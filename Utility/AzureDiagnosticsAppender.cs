using System.Diagnostics;
using log4net.Appender;
using log4net.Core;

namespace GigyaJWTRestPOC.Utility
{
    public class AzureDiagnosticsAppender : AppenderSkeleton
    {
        protected override void Append(LoggingEvent loggingEvent)
        {
            var message = RenderLoggingEvent(loggingEvent);

            if (loggingEvent.Level >= Level.Error)
            {
                Trace.TraceError(message);
            }
            else if (loggingEvent.Level >= Level.Warn)
            {
                Trace.TraceWarning(message);
            }
            else
            {
                // Everything else (Info, Debug, etc.) sent to Azure as Information
                // This bypasses Azure's filter that ignores generic Trace.Write!
                Trace.TraceInformation(message);
            }
            
            // Forces Azure's buffer to flush dynamically so it streams instantly!
            Trace.Flush();
        }
    }
}
