using System.Collections.Generic;

namespace Example
{
    public struct AuthorizationPolicies
    {
        public const string PolicyString = "Some policy";
        private const string PolicyScope = "Some Scope";
        public static readonly Dictionary<string, string[]> ScopePolicies = new Dictionary<string,string[]> {
            { PolicyString, new[] { PolicyScope } }
        };

    }
}