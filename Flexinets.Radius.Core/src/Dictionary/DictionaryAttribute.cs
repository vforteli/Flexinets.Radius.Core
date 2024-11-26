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
        public DictionaryAttribute(string name, byte code, string type)
        {
            Code = code;
            Name = name;
            Type = type;
        }
    }
}