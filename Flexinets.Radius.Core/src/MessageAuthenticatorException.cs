using System;

namespace Flexinets.Radius.Core
{
    public class MessageAuthenticatorException : Exception
    {
        public MessageAuthenticatorException(string message)
            : base(message)
        {
        }
    }
}