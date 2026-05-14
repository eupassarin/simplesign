namespace SimpleSign.HtmlToPdf.Fonts;

/// <summary>
/// Glyph width tables for standard PDF fonts.
/// Widths are in 1/1000th of a font unit (multiply by fontSize/1000 to get points).
/// Data derived from Adobe AFM specifications.
/// </summary>
internal static class FontMetrics
{
    private const int FirstChar = 32;
    private const int CourierWidth = 600;

    // Helvetica Regular — WinAnsiEncoding, codes 32–255
    private static readonly ushort[] HelveticaWidths =
    [
        278, 278, 355, 556, 556, 889, 667, 191, // 32–39
        333, 333, 389, 584, 278, 333, 278, 278, // 40–47
        556, 556, 556, 556, 556, 556, 556, 556, // 48–55
        556, 556, 278, 278, 584, 584, 584, 556, // 56–63
        1015, 667, 667, 722, 722, 667, 611, 778, // 64–71
        722, 278, 500, 667, 556, 833, 722, 778, // 72–79
        667, 778, 722, 667, 611, 722, 667, 944, // 80–87
        667, 667, 611, 278, 278, 278, 469, 556, // 88–95
        333, 556, 556, 500, 556, 556, 278, 556, // 96–103
        556, 222, 222, 500, 222, 833, 556, 556, // 104–111
        556, 556, 333, 500, 278, 556, 500, 722, // 112–119
        500, 500, 500, 334, 260, 334, 584,       // 120–126
        278,  // 127 DEL
        556,  // 128 Euro
        278,  // 129 undefined
        222,  // 130 quotesinglbase
        556,  // 131 florin
        333,  // 132 quotedblbase
        1000, // 133 ellipsis
        556,  // 134 dagger
        556,  // 135 daggerdbl
        333,  // 136 circumflex
        1000, // 137 perthousand
        667,  // 138 Scaron
        333,  // 139 guilsinglleft
        1000, // 140 OE
        278,  // 141 undefined
        611,  // 142 Zcaron
        278,  // 143 undefined
        278,  // 144 undefined
        222,  // 145 quoteleft
        222,  // 146 quoteright
        333,  // 147 quotedblleft
        333,  // 148 quotedblright
        350,  // 149 bullet
        556,  // 150 endash
        1000, // 151 emdash
        333,  // 152 tilde
        1000, // 153 trademark
        500,  // 154 scaron
        333,  // 155 guilsinglright
        944,  // 156 oe
        278,  // 157 undefined
        500,  // 158 zcaron
        667,  // 159 Ydieresis
        278,  // 160 nbspace
        333,  // 161 exclamdown
        556,  // 162 cent
        556,  // 163 sterling
        556,  // 164 currency
        556,  // 165 yen
        260,  // 166 brokenbar
        556,  // 167 section
        333,  // 168 dieresis
        737,  // 169 copyright
        370,  // 170 ordfeminine
        556,  // 171 guillemotleft
        584,  // 172 logicalnot
        333,  // 173 softhyphen
        737,  // 174 registered
        333,  // 175 macron
        400,  // 176 degree
        584,  // 177 plusminus
        333,  // 178 twosuperior
        333,  // 179 threesuperior
        333,  // 180 acute
        556,  // 181 mu
        537,  // 182 paragraph
        278,  // 183 periodcentered
        333,  // 184 cedilla
        333,  // 185 onesuperior
        365,  // 186 ordmasculine
        556,  // 187 guillemotright
        834,  // 188 onequarter
        834,  // 189 onehalf
        834,  // 190 threequarters
        611,  // 191 questiondown
        667,  // 192 Agrave
        667,  // 193 Aacute
        667,  // 194 Acircumflex
        667,  // 195 Atilde
        667,  // 196 Adieresis
        667,  // 197 Aring
        1000, // 198 AE
        722,  // 199 Ccedilla
        667,  // 200 Egrave
        667,  // 201 Eacute
        667,  // 202 Ecircumflex
        667,  // 203 Edieresis
        278,  // 204 Igrave
        278,  // 205 Iacute
        278,  // 206 Icircumflex
        278,  // 207 Idieresis
        722,  // 208 Eth
        722,  // 209 Ntilde
        778,  // 210 Ograve
        778,  // 211 Oacute
        778,  // 212 Ocircumflex
        778,  // 213 Otilde
        778,  // 214 Odieresis
        584,  // 215 multiply
        778,  // 216 Oslash
        722,  // 217 Ugrave
        722,  // 218 Uacute
        722,  // 219 Ucircumflex
        722,  // 220 Udieresis
        667,  // 221 Yacute
        667,  // 222 Thorn
        611,  // 223 germandbls
        556,  // 224 agrave
        556,  // 225 aacute
        556,  // 226 acircumflex
        556,  // 227 atilde
        556,  // 228 adieresis
        556,  // 229 aring
        889,  // 230 ae
        500,  // 231 ccedilla
        556,  // 232 egrave
        556,  // 233 eacute
        556,  // 234 ecircumflex
        556,  // 235 edieresis
        278,  // 236 igrave
        278,  // 237 iacute
        278,  // 238 icircumflex
        278,  // 239 idieresis
        556,  // 240 eth
        556,  // 241 ntilde
        556,  // 242 ograve
        556,  // 243 oacute
        556,  // 244 ocircumflex
        556,  // 245 otilde
        556,  // 246 odieresis
        584,  // 247 divide
        611,  // 248 oslash
        556,  // 249 ugrave
        556,  // 250 uacute
        556,  // 251 ucircumflex
        556,  // 252 udieresis
        500,  // 253 yacute
        556,  // 254 thorn
        500   // 255 ydieresis
    ];

    // Helvetica Bold — WinAnsiEncoding, codes 32–255
    private static readonly ushort[] HelveticaBoldWidths =
    [
        278, 333, 474, 556, 556, 889, 722, 238, // 32–39
        333, 333, 389, 584, 278, 333, 278, 278, // 40–47
        556, 556, 556, 556, 556, 556, 556, 556, // 48–55
        556, 556, 333, 333, 584, 584, 584, 611, // 56–63
        975, 722, 722, 722, 722, 667, 611, 778, // 64–71
        722, 278, 556, 722, 611, 833, 722, 778, // 72–79
        667, 778, 722, 667, 611, 722, 667, 944, // 80–87
        667, 667, 611, 333, 278, 333, 584, 556, // 88–95
        333, 556, 611, 556, 611, 556, 333, 611, // 96–103
        611, 278, 278, 556, 278, 889, 611, 611, // 104–111
        611, 611, 389, 556, 333, 611, 556, 778, // 112–119
        556, 556, 500, 389, 280, 389, 584,       // 120–126
        278,  // 127 DEL
        556,  // 128 Euro
        278,  // 129 undefined
        278,  // 130 quotesinglbase
        556,  // 131 florin
        500,  // 132 quotedblbase
        1000, // 133 ellipsis
        556,  // 134 dagger
        556,  // 135 daggerdbl
        333,  // 136 circumflex
        1000, // 137 perthousand
        667,  // 138 Scaron
        333,  // 139 guilsinglleft
        1000, // 140 OE
        278,  // 141 undefined
        611,  // 142 Zcaron
        278,  // 143 undefined
        278,  // 144 undefined
        278,  // 145 quoteleft
        278,  // 146 quoteright
        500,  // 147 quotedblleft
        500,  // 148 quotedblright
        350,  // 149 bullet
        556,  // 150 endash
        1000, // 151 emdash
        333,  // 152 tilde
        1000, // 153 trademark
        556,  // 154 scaron
        333,  // 155 guilsinglright
        944,  // 156 oe
        278,  // 157 undefined
        500,  // 158 zcaron
        667,  // 159 Ydieresis
        278,  // 160 nbspace
        333,  // 161 exclamdown
        556,  // 162 cent
        556,  // 163 sterling
        556,  // 164 currency
        556,  // 165 yen
        280,  // 166 brokenbar
        556,  // 167 section
        333,  // 168 dieresis
        737,  // 169 copyright
        370,  // 170 ordfeminine
        556,  // 171 guillemotleft
        584,  // 172 logicalnot
        333,  // 173 softhyphen
        737,  // 174 registered
        333,  // 175 macron
        400,  // 176 degree
        584,  // 177 plusminus
        333,  // 178 twosuperior
        333,  // 179 threesuperior
        333,  // 180 acute
        611,  // 181 mu
        556,  // 182 paragraph
        278,  // 183 periodcentered
        333,  // 184 cedilla
        333,  // 185 onesuperior
        365,  // 186 ordmasculine
        556,  // 187 guillemotright
        834,  // 188 onequarter
        834,  // 189 onehalf
        834,  // 190 threequarters
        611,  // 191 questiondown
        722,  // 192 Agrave
        722,  // 193 Aacute
        722,  // 194 Acircumflex
        722,  // 195 Atilde
        722,  // 196 Adieresis
        722,  // 197 Aring
        1000, // 198 AE
        722,  // 199 Ccedilla
        667,  // 200 Egrave
        667,  // 201 Eacute
        667,  // 202 Ecircumflex
        667,  // 203 Edieresis
        278,  // 204 Igrave
        278,  // 205 Iacute
        278,  // 206 Icircumflex
        278,  // 207 Idieresis
        722,  // 208 Eth
        722,  // 209 Ntilde
        778,  // 210 Ograve
        778,  // 211 Oacute
        778,  // 212 Ocircumflex
        778,  // 213 Otilde
        778,  // 214 Odieresis
        584,  // 215 multiply
        778,  // 216 Oslash
        722,  // 217 Ugrave
        722,  // 218 Uacute
        722,  // 219 Ucircumflex
        722,  // 220 Udieresis
        667,  // 221 Yacute
        667,  // 222 Thorn
        611,  // 223 germandbls
        556,  // 224 agrave
        611,  // 225 aacute
        556,  // 226 acircumflex
        556,  // 227 atilde
        556,  // 228 adieresis
        556,  // 229 aring
        889,  // 230 ae
        556,  // 231 ccedilla
        556,  // 232 egrave
        556,  // 233 eacute
        556,  // 234 ecircumflex
        556,  // 235 edieresis
        278,  // 236 igrave
        278,  // 237 iacute
        278,  // 238 icircumflex
        278,  // 239 idieresis
        611,  // 240 eth
        611,  // 241 ntilde
        611,  // 242 ograve
        611,  // 243 oacute
        611,  // 244 ocircumflex
        611,  // 245 otilde
        611,  // 246 odieresis
        584,  // 247 divide
        611,  // 248 oslash
        611,  // 249 ugrave
        611,  // 250 uacute
        611,  // 251 ucircumflex
        611,  // 252 udieresis
        556,  // 253 yacute
        611,  // 254 thorn
        556   // 255 ydieresis
    ];

    // Times-Roman Regular — WinAnsiEncoding, codes 32–255
    private static readonly ushort[] TimesRomanWidths =
    [
        250, 333, 408, 500, 500, 833, 778, 180, // 32–39
        333, 333, 500, 564, 250, 333, 250, 278, // 40–47
        500, 500, 500, 500, 500, 500, 500, 500, // 48–55
        500, 500, 278, 278, 564, 564, 564, 444, // 56–63
        921, 722, 667, 667, 722, 611, 556, 722, // 64–71
        722, 333, 389, 722, 611, 889, 722, 722, // 72–79
        556, 722, 667, 556, 611, 722, 722, 944, // 80–87
        722, 722, 611, 333, 278, 333, 469, 500, // 88–95
        333, 444, 500, 444, 500, 444, 333, 500, // 96–103
        500, 278, 278, 500, 278, 778, 500, 500, // 104–111
        500, 500, 333, 389, 278, 500, 500, 722, // 112–119
        500, 500, 444, 480, 200, 480, 541,       // 120–126
        250,  // 127 DEL
        500,  // 128 Euro
        250,  // 129 undefined
        333,  // 130 quotesinglbase
        500,  // 131 florin
        444,  // 132 quotedblbase
        1000, // 133 ellipsis
        500,  // 134 dagger
        500,  // 135 daggerdbl
        333,  // 136 circumflex
        1000, // 137 perthousand
        556,  // 138 Scaron
        333,  // 139 guilsinglleft
        889,  // 140 OE
        250,  // 141 undefined
        611,  // 142 Zcaron
        250,  // 143 undefined
        250,  // 144 undefined
        333,  // 145 quoteleft
        333,  // 146 quoteright
        444,  // 147 quotedblleft
        444,  // 148 quotedblright
        350,  // 149 bullet
        500,  // 150 endash
        1000, // 151 emdash
        333,  // 152 tilde
        980,  // 153 trademark
        389,  // 154 scaron
        333,  // 155 guilsinglright
        722,  // 156 oe
        250,  // 157 undefined
        444,  // 158 zcaron
        722,  // 159 Ydieresis
        250,  // 160 nbspace
        333,  // 161 exclamdown
        500,  // 162 cent
        500,  // 163 sterling
        500,  // 164 currency
        500,  // 165 yen
        200,  // 166 brokenbar
        500,  // 167 section
        333,  // 168 dieresis
        760,  // 169 copyright
        276,  // 170 ordfeminine
        500,  // 171 guillemotleft
        564,  // 172 logicalnot
        333,  // 173 softhyphen
        760,  // 174 registered
        333,  // 175 macron
        400,  // 176 degree
        564,  // 177 plusminus
        300,  // 178 twosuperior
        300,  // 179 threesuperior
        333,  // 180 acute
        500,  // 181 mu
        453,  // 182 paragraph
        250,  // 183 periodcentered
        333,  // 184 cedilla
        300,  // 185 onesuperior
        310,  // 186 ordmasculine
        500,  // 187 guillemotright
        750,  // 188 onequarter
        750,  // 189 onehalf
        750,  // 190 threequarters
        444,  // 191 questiondown
        722,  // 192 Agrave
        722,  // 193 Aacute
        722,  // 194 Acircumflex
        722,  // 195 Atilde
        722,  // 196 Adieresis
        722,  // 197 Aring
        889,  // 198 AE
        667,  // 199 Ccedilla
        611,  // 200 Egrave
        611,  // 201 Eacute
        611,  // 202 Ecircumflex
        611,  // 203 Edieresis
        333,  // 204 Igrave
        333,  // 205 Iacute
        333,  // 206 Icircumflex
        333,  // 207 Idieresis
        722,  // 208 Eth
        722,  // 209 Ntilde
        722,  // 210 Ograve
        722,  // 211 Oacute
        722,  // 212 Ocircumflex
        722,  // 213 Otilde
        722,  // 214 Odieresis
        564,  // 215 multiply
        722,  // 216 Oslash
        722,  // 217 Ugrave
        722,  // 218 Uacute
        722,  // 219 Ucircumflex
        722,  // 220 Udieresis
        722,  // 221 Yacute
        556,  // 222 Thorn
        500,  // 223 germandbls
        444,  // 224 agrave
        444,  // 225 aacute
        444,  // 226 acircumflex
        444,  // 227 atilde
        444,  // 228 adieresis
        444,  // 229 aring
        667,  // 230 ae
        444,  // 231 ccedilla
        444,  // 232 egrave
        444,  // 233 eacute
        444,  // 234 ecircumflex
        444,  // 235 edieresis
        278,  // 236 igrave
        278,  // 237 iacute
        278,  // 238 icircumflex
        278,  // 239 idieresis
        500,  // 240 eth
        500,  // 241 ntilde
        500,  // 242 ograve
        500,  // 243 oacute
        500,  // 244 ocircumflex
        500,  // 245 otilde
        500,  // 246 odieresis
        564,  // 247 divide
        500,  // 248 oslash
        500,  // 249 ugrave
        500,  // 250 uacute
        500,  // 251 ucircumflex
        500,  // 252 udieresis
        500,  // 253 yacute
        500,  // 254 thorn
        500   // 255 ydieresis
    ];

    // Times-Bold — WinAnsiEncoding, codes 32–255
    private static readonly ushort[] TimesBoldWidths =
    [
        250, 333, 555, 500, 500, 1000, 833, 278, // 32–39
        333, 333, 500, 570, 250, 333, 250, 278,  // 40–47
        500, 500, 500, 500, 500, 500, 500, 500,  // 48–55
        500, 500, 333, 333, 570, 570, 570, 500,  // 56–63
        930, 722, 667, 722, 722, 667, 611, 778,  // 64–71
        778, 389, 500, 778, 667, 944, 722, 778,  // 72–79
        611, 778, 722, 556, 667, 722, 722, 1000, // 80–87
        722, 722, 667, 333, 278, 333, 581, 500,  // 88–95
        333, 500, 556, 444, 556, 444, 333, 500,  // 96–103
        556, 278, 333, 556, 278, 833, 556, 500,  // 104–111
        556, 556, 444, 389, 333, 556, 500, 722,  // 112–119
        500, 500, 444, 394, 220, 394, 520,        // 120–126
        250,  // 127 DEL
        500,  // 128 Euro
        250,  // 129 undefined
        333,  // 130 quotesinglbase
        500,  // 131 florin
        500,  // 132 quotedblbase
        1000, // 133 ellipsis
        500,  // 134 dagger
        500,  // 135 daggerdbl
        333,  // 136 circumflex
        1000, // 137 perthousand
        556,  // 138 Scaron
        333,  // 139 guilsinglleft
        1000, // 140 OE
        250,  // 141 undefined
        667,  // 142 Zcaron
        250,  // 143 undefined
        250,  // 144 undefined
        333,  // 145 quoteleft
        333,  // 146 quoteright
        500,  // 147 quotedblleft
        500,  // 148 quotedblright
        350,  // 149 bullet
        500,  // 150 endash
        1000, // 151 emdash
        333,  // 152 tilde
        1000, // 153 trademark
        389,  // 154 scaron
        333,  // 155 guilsinglright
        722,  // 156 oe
        250,  // 157 undefined
        444,  // 158 zcaron
        722,  // 159 Ydieresis
        250,  // 160 nbspace
        333,  // 161 exclamdown
        500,  // 162 cent
        500,  // 163 sterling
        500,  // 164 currency
        500,  // 165 yen
        220,  // 166 brokenbar
        500,  // 167 section
        333,  // 168 dieresis
        747,  // 169 copyright
        300,  // 170 ordfeminine
        500,  // 171 guillemotleft
        570,  // 172 logicalnot
        333,  // 173 softhyphen
        747,  // 174 registered
        333,  // 175 macron
        400,  // 176 degree
        570,  // 177 plusminus
        300,  // 178 twosuperior
        300,  // 179 threesuperior
        333,  // 180 acute
        556,  // 181 mu
        540,  // 182 paragraph
        278,  // 183 periodcentered
        333,  // 184 cedilla
        300,  // 185 onesuperior
        330,  // 186 ordmasculine
        500,  // 187 guillemotright
        750,  // 188 onequarter
        750,  // 189 onehalf
        750,  // 190 threequarters
        500,  // 191 questiondown
        722,  // 192 Agrave
        722,  // 193 Aacute
        722,  // 194 Acircumflex
        722,  // 195 Atilde
        722,  // 196 Adieresis
        722,  // 197 Aring
        1000, // 198 AE
        722,  // 199 Ccedilla
        667,  // 200 Egrave
        667,  // 201 Eacute
        667,  // 202 Ecircumflex
        667,  // 203 Edieresis
        389,  // 204 Igrave
        389,  // 205 Iacute
        389,  // 206 Icircumflex
        389,  // 207 Idieresis
        722,  // 208 Eth
        722,  // 209 Ntilde
        778,  // 210 Ograve
        778,  // 211 Oacute
        778,  // 212 Ocircumflex
        778,  // 213 Otilde
        778,  // 214 Odieresis
        570,  // 215 multiply
        778,  // 216 Oslash
        722,  // 217 Ugrave
        722,  // 218 Uacute
        722,  // 219 Ucircumflex
        722,  // 220 Udieresis
        722,  // 221 Yacute
        611,  // 222 Thorn
        556,  // 223 germandbls
        500,  // 224 agrave
        500,  // 225 aacute
        500,  // 226 acircumflex
        500,  // 227 atilde
        500,  // 228 adieresis
        500,  // 229 aring
        722,  // 230 ae
        444,  // 231 ccedilla
        444,  // 232 egrave
        444,  // 233 eacute
        444,  // 234 ecircumflex
        444,  // 235 edieresis
        278,  // 236 igrave
        278,  // 237 iacute
        278,  // 238 icircumflex
        278,  // 239 idieresis
        500,  // 240 eth
        556,  // 241 ntilde
        500,  // 242 ograve
        500,  // 243 oacute
        500,  // 244 ocircumflex
        500,  // 245 otilde
        500,  // 246 odieresis
        570,  // 247 divide
        500,  // 248 oslash
        556,  // 249 ugrave
        556,  // 250 uacute
        556,  // 251 ucircumflex
        556,  // 252 udieresis
        500,  // 253 yacute
        556,  // 254 thorn
        500   // 255 ydieresis
    ];

    /// <summary>Gets the character width for a standard PDF font.</summary>
    /// <param name="pdfFontName">PDF base font name (e.g., "Helvetica-Bold").</param>
    /// <param name="charCode">Character code (ASCII/WinAnsi).</param>
    /// <returns>Width in 1/1000 font units.</returns>
    internal static int GetCharWidth(string pdfFontName, char charCode)
    {
        ushort[] widths = GetWidthTable(pdfFontName);

        // Courier is monospaced — all characters have the same width
        if (widths.Length == 0)
        {
            return CourierWidth;
        }

        int code = WinAnsiEncoding.MapToWinAnsi(charCode);
        if (code < 0)
        {
            return widths[0]; // unmappable → default to space width
        }

        int index = code - FirstChar;
        if (index < 0 || index >= widths.Length)
        {
            return widths[0]; // default to space width
        }

        return widths[index];
    }

    private static ushort[] GetWidthTable(string pdfFontName)
    {
        return pdfFontName switch
        {
            "Helvetica" or "Helvetica-Oblique" => HelveticaWidths,
            "Helvetica-Bold" or "Helvetica-BoldOblique" => HelveticaBoldWidths,
            "Times-Roman" or "Times-Italic" => TimesRomanWidths,
            "Times-Bold" or "Times-BoldItalic" => TimesBoldWidths,
            "Courier" or "Courier-Bold" or "Courier-Oblique" or "Courier-BoldOblique" => [],
            _ => HelveticaWidths // fallback
        };
    }
}
