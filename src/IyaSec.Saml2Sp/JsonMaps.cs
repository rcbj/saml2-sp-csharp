// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

using System.Collections;
using System.Globalization;
using System.Text.Json;

namespace IyaSec.Saml;

static class JsonMaps
{
    internal static object? Parse(string text)
    {
        using var doc = JsonDocument.Parse(text);
        return ConfigFile.FromElement(doc.RootElement);
    }

    internal static string Stringify(object? value)
    {
        using var stream = new MemoryStream();
        using (var writer = new Utf8JsonWriter(stream))
            Write(writer, value);
        return System.Text.Encoding.UTF8.GetString(stream.ToArray());
    }

    static void Write(Utf8JsonWriter writer, object? value)
    {
        switch (value)
        {
            case null:
                writer.WriteNullValue();
                return;
            case bool flag:
                writer.WriteBooleanValue(flag);
                return;
            case string text:
                writer.WriteStringValue(text);
                return;
            case byte or sbyte or short or ushort or int or uint or long or ulong:
                writer.WriteNumberValue(Convert.ToInt64(value, CultureInfo.InvariantCulture));
                return;
            case float or double or decimal:
                writer.WriteNumberValue(Convert.ToDouble(value, CultureInfo.InvariantCulture));
                return;
            case IDictionary map:
                writer.WriteStartObject();
                foreach (DictionaryEntry pair in map)
                {
                    writer.WritePropertyName(pair.Key?.ToString() ?? "");
                    Write(writer, pair.Value);
                }
                writer.WriteEndObject();
                return;
            case IEnumerable list:
                writer.WriteStartArray();
                foreach (var item in list) Write(writer, item);
                writer.WriteEndArray();
                return;
            default:
                writer.WriteStringValue(Convert.ToString(value, CultureInfo.InvariantCulture));
                return;
        }
    }
}
