using System.Globalization;

namespace SimpleSign.HtmlToPdf.Rendering.Svg;

/// <summary>A path segment in absolute coordinates: move, line, cubic Bézier or close.</summary>
internal readonly record struct PathSegment(char Kind, float X1, float Y1, float X2, float Y2, float X, float Y);

/// <summary>Parses SVG path data and number lists. Quadratic curves and arcs become cubic Béziers.</summary>
internal static class SvgPathParser
{
    private const int MaxSegments = 1_000_000;

    /// <summary>Parses a list of numbers separated by whitespace and/or commas (e.g. <c>points</c>, <c>viewBox</c>).</summary>
    public static float[] ParseNumbers(string text)
    {
        var numbers = new List<float>();
        int i = 0;
        while (TryReadNumber(text, ref i, out float n))
        {
            numbers.Add(n);
        }

        return [.. numbers];
    }

    /// <summary>Parses path data; invalid data stops parsing at the error, like browsers.</summary>
    public static List<PathSegment> Parse(string? d)
    {
        var segments = new List<PathSegment>();
        if (string.IsNullOrWhiteSpace(d))
        {
            return segments;
        }

        int i = 0;
        char command = ' ';
        float cx = 0, cy = 0;          // current point
        float sx = 0, sy = 0;          // subpath start
        float lastCtrlX = 0, lastCtrlY = 0;
        char lastKind = ' ';
        while (segments.Count < MaxSegments)
        {
            SkipSeparators(d, ref i);
            if (i >= d.Length)
            {
                break;
            }

            if (char.IsLetter(d[i]) && d[i] is not ('e' or 'E'))
            {
                command = d[i++];
            }
            else if (command == ' ')
            {
                break;
            }

            bool rel = char.IsLower(command);
            char upper = char.ToUpperInvariant(command);
            float ox = rel ? cx : 0, oy = rel ? cy : 0;
            switch (upper)
            {
                case 'Z':
                    segments.Add(new PathSegment('Z', 0, 0, 0, 0, sx, sy));
                    cx = sx;
                    cy = sy;
                    lastKind = 'Z';

                    // Z takes no arguments; a following number is an error.
                    command = ' ';
                    continue;

                case 'M':
                    if (!Read2(d, ref i, out float mx, out float my))
                    {
                        return segments;
                    }

                    cx = ox + mx;
                    cy = oy + my;
                    sx = cx;
                    sy = cy;
                    segments.Add(new PathSegment('M', 0, 0, 0, 0, cx, cy));

                    // Further coordinate pairs are implicit line-tos.
                    command = rel ? 'l' : 'L';
                    lastKind = 'M';
                    continue;

                case 'L':
                    if (!Read2(d, ref i, out float lx, out float ly))
                    {
                        return segments;
                    }

                    cx = ox + lx;
                    cy = oy + ly;
                    segments.Add(Line(cx, cy));
                    break;

                case 'H':
                    if (!TryReadNumber(d, ref i, out float hx))
                    {
                        return segments;
                    }

                    cx = ox + hx;
                    segments.Add(Line(cx, cy));
                    break;

                case 'V':
                    if (!TryReadNumber(d, ref i, out float vy))
                    {
                        return segments;
                    }

                    cy = oy + vy;
                    segments.Add(Line(cx, cy));
                    break;

                case 'C':
                    {
                        if (!Read2(d, ref i, out float x1, out float y1) || !Read2(d, ref i, out float x2, out float y2) || !Read2(d, ref i, out float x, out float y))
                        {
                            return segments;
                        }

                        segments.Add(new PathSegment('C', ox + x1, oy + y1, ox + x2, oy + y2, ox + x, oy + y));
                        (lastCtrlX, lastCtrlY) = (ox + x2, oy + y2);
                        (cx, cy) = (ox + x, oy + y);
                        lastKind = 'C';
                        continue;
                    }

                case 'S':
                    {
                        if (!Read2(d, ref i, out float x2, out float y2) || !Read2(d, ref i, out float x, out float y))
                        {
                            return segments;
                        }

                        (float x1, float y1) = lastKind == 'C' ? ((2 * cx) - lastCtrlX, (2 * cy) - lastCtrlY) : (cx, cy);
                        segments.Add(new PathSegment('C', x1, y1, ox + x2, oy + y2, ox + x, oy + y));
                        (lastCtrlX, lastCtrlY) = (ox + x2, oy + y2);
                        (cx, cy) = (ox + x, oy + y);
                        lastKind = 'C';
                        continue;
                    }

                case 'Q':
                    {
                        if (!Read2(d, ref i, out float qx, out float qy) || !Read2(d, ref i, out float x, out float y))
                        {
                            return segments;
                        }

                        segments.Add(Quadratic(cx, cy, ox + qx, oy + qy, ox + x, oy + y));
                        (lastCtrlX, lastCtrlY) = (ox + qx, oy + qy);
                        (cx, cy) = (ox + x, oy + y);
                        lastKind = 'Q';
                        continue;
                    }

                case 'T':
                    {
                        if (!Read2(d, ref i, out float x, out float y))
                        {
                            return segments;
                        }

                        (float qx, float qy) = lastKind == 'Q' ? ((2 * cx) - lastCtrlX, (2 * cy) - lastCtrlY) : (cx, cy);
                        segments.Add(Quadratic(cx, cy, qx, qy, ox + x, oy + y));
                        (lastCtrlX, lastCtrlY) = (qx, qy);
                        (cx, cy) = (ox + x, oy + y);
                        lastKind = 'Q';
                        continue;
                    }

                case 'A':
                    {
                        if (!TryReadNumber(d, ref i, out float rx) || !TryReadNumber(d, ref i, out float ry) || !TryReadNumber(d, ref i, out float angle)
                            || !TryReadFlag(d, ref i, out bool large) || !TryReadFlag(d, ref i, out bool sweep) || !Read2(d, ref i, out float x, out float y))
                        {
                            return segments;
                        }

                        AppendArc(segments, cx, cy, rx, ry, angle, large, sweep, ox + x, oy + y);
                        (cx, cy) = (ox + x, oy + y);
                        break;
                    }

                default:
                    return segments;
            }

            lastKind = upper;
        }

        return segments;
    }

    private static PathSegment Line(float x, float y) => new('L', 0, 0, 0, 0, x, y);

    private static PathSegment Quadratic(float x0, float y0, float qx, float qy, float x, float y) => new(
        'C',
        x0 + (2f / 3f * (qx - x0)), y0 + (2f / 3f * (qy - y0)),
        x + (2f / 3f * (qx - x)), y + (2f / 3f * (qy - y)),
        x, y);

    /// <summary>Converts an SVG elliptical arc (endpoint parameterization) to cubic Béziers.</summary>
    internal static void AppendArc(List<PathSegment> segments, float x0, float y0, float rx, float ry, float angleDeg, bool largeArc, bool sweep, float x, float y)
    {
        if ((x0 == x && y0 == y))
        {
            return;
        }

        rx = Math.Abs(rx);
        ry = Math.Abs(ry);
        if (rx < 1e-6f || ry < 1e-6f)
        {
            segments.Add(Line(x, y));
            return;
        }

        double phi = angleDeg * Math.PI / 180;
        double cos = Math.Cos(phi), sin = Math.Sin(phi);
        double dx = (x0 - x) / 2.0, dy = (y0 - y) / 2.0;
        double x1p = (cos * dx) + (sin * dy);
        double y1p = (-sin * dx) + (cos * dy);

        double rxs = rx * (double)rx, rys = ry * (double)ry;
        double lambda = (x1p * x1p / rxs) + (y1p * y1p / rys);
        if (lambda > 1)
        {
            double scale = Math.Sqrt(lambda);
            rxs *= lambda;
            rys *= lambda;
            rx = (float)(rx * scale);
            ry = (float)(ry * scale);
        }

        double num = (rxs * rys) - (rxs * y1p * y1p) - (rys * x1p * x1p);
        double den = (rxs * y1p * y1p) + (rys * x1p * x1p);
        double coef = den == 0 ? 0 : Math.Sqrt(Math.Max(0, num / den)) * (largeArc == sweep ? -1 : 1);
        double cxp = coef * rx * y1p / ry;
        double cyp = -coef * ry * x1p / rx;
        double centerX = (cos * cxp) - (sin * cyp) + ((x0 + x) / 2.0);
        double centerY = (sin * cxp) + (cos * cyp) + ((y0 + y) / 2.0);

        double theta1 = Angle(1, 0, (x1p - cxp) / rx, (y1p - cyp) / ry);
        double delta = Angle((x1p - cxp) / rx, (y1p - cyp) / ry, (-x1p - cxp) / rx, (-y1p - cyp) / ry);
        if (!sweep && delta > 0)
        {
            delta -= 2 * Math.PI;
        }
        else if (sweep && delta < 0)
        {
            delta += 2 * Math.PI;
        }

        int parts = Math.Max(1, (int)Math.Ceiling(Math.Abs(delta) / (Math.PI / 2)));
        double step = delta / parts;
        double k = 4.0 / 3.0 * Math.Tan(step / 4);
        double t = theta1;
        for (int p = 0; p < parts; p++)
        {
            double c1 = Math.Cos(t), s1 = Math.Sin(t);
            double c2 = Math.Cos(t + step), s2 = Math.Sin(t + step);
            (double ax, double ay) = Map(c1 - (k * s1), s1 + (k * c1));
            (double bx, double by) = Map(c2 + (k * s2), s2 - (k * c2));
            (double ex, double ey) = Map(c2, s2);
            segments.Add(new PathSegment('C', (float)ax, (float)ay, (float)bx, (float)by, (float)ex, (float)ey));
            t += step;
        }

        // Land exactly on the requested endpoint.
        PathSegment last = segments[^1];
        segments[^1] = last with { X = x, Y = y };

        (double, double) Map(double ux, double uy) =>
            ((cos * rx * ux) - (sin * ry * uy) + centerX, (sin * rx * ux) + (cos * ry * uy) + centerY);
    }

    private static double Angle(double ux, double uy, double vx, double vy)
    {
        double dot = (ux * vx) + (uy * vy);
        double len = Math.Sqrt(((ux * ux) + (uy * uy)) * ((vx * vx) + (vy * vy)));
        double angle = Math.Acos(Math.Clamp(len == 0 ? 1 : dot / len, -1, 1));
        return (ux * vy) - (uy * vx) < 0 ? -angle : angle;
    }

    private static bool Read2(string s, ref int i, out float a, out float b)
    {
        b = 0;
        return TryReadNumber(s, ref i, out a) && TryReadNumber(s, ref i, out b);
    }

    private static void SkipSeparators(string s, ref int i)
    {
        while (i < s.Length && (char.IsWhiteSpace(s[i]) || s[i] == ','))
        {
            i++;
        }
    }

    /// <summary>Arc flags may be written without separators ("a1 1 0 00 1 1").</summary>
    private static bool TryReadFlag(string s, ref int i, out bool flag)
    {
        SkipSeparators(s, ref i);
        flag = false;
        if (i < s.Length && s[i] is '0' or '1')
        {
            flag = s[i] == '1';
            i++;
            return true;
        }

        return false;
    }

    internal static bool TryReadNumber(string s, ref int i, out float value)
    {
        SkipSeparators(s, ref i);
        value = 0;
        int start = i;
        if (i < s.Length && s[i] is '+' or '-')
        {
            i++;
        }

        bool digits = false, dot = false;
        while (i < s.Length)
        {
            char c = s[i];
            if (char.IsAsciiDigit(c))
            {
                digits = true;
                i++;
            }
            else if (c == '.' && !dot)
            {
                dot = true;
                i++;
            }
            else
            {
                break;
            }
        }

        if (!digits)
        {
            i = start;
            return false;
        }

        if (i < s.Length && s[i] is 'e' or 'E' && i + 1 < s.Length && (char.IsAsciiDigit(s[i + 1]) || (s[i + 1] is '+' or '-' && i + 2 < s.Length && char.IsAsciiDigit(s[i + 2]))))
        {
            i += 2;
            while (i < s.Length && char.IsAsciiDigit(s[i]))
            {
                i++;
            }
        }

        if (!float.TryParse(s.AsSpan(start, i - start), NumberStyles.Float, CultureInfo.InvariantCulture, out value) || !float.IsFinite(value))
        {
            i = start;
            return false;
        }

        return true;
    }
}
