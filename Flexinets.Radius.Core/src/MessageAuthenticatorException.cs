using System;

namespace Flexinets.Radius.Core
{
    public class MessageAuthenticatorException : InvalidOperationException
    {
        public MessageAuthenticatorException(string message) : base(message)
        {
        }
    }

    public class MissingMessageAuthenticatorException : MessageAuthenticatorException
    {
        public MissingMessageAuthenticatorException(string message) : base(message)
        {
        }
    }

    public class InvalidMessageAuthenticatorException : MessageAuthenticatorException
    {
        public InvalidMessageAuthenticatorException(string message) : base(message)
        {
        }
    }
}