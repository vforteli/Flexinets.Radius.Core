namespace Flexinets.Radius.Core
{
    public class DictionaryAttribute
    {
        public readonly byte Code;
        public readonly string Name;
        public readonly string Type;

        /// <summary>
        /// Create a dictionary rfc attribute
        /// </summary>
        /// <param name="name"></param>
        /// <param name="code"></param>
        /// <param name="type"></param>
        public DictionaryAttribute(string name, byte code, string type)
        {
            Code = code;
            Name = name;
            Type = type;
        }
    }
}
