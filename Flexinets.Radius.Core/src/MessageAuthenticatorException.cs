using System;

namespace Flexinets.Radius.Core
{
    public class MessageAuthenticatorException : InvalidOperationException
    {
        public MessageAuthenticatorException(string message)
            : base(message)
        {
        }
    }
}