#region License
/*
CryptSharp
Copyright (c) 2011, 2013 James F. Bellinger <http://www.zer7.com/software/cryptsharp>

Permission to use, copy, modify, and/or distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
*/
#endregion

using System;

namespace CryptSharp.SCryptSubset.PCL
{
    // Source: http://cr.yp.to/salsa20.html
    /// <summary>
    /// Implements the Salsa20 hash function.
    /// </summary>
    public static class Salsa20Core
    {
        static uint R(uint a, int b) { return (a << b) | (a >> (32 - b)); }

        /// <summary>
        /// Applies the Salsa20 hash function.
        /// It maps a 16 element input to an output of the same size.
        /// </summary>
        /// <param name="rounds">The number of rounds. SCrypt uses 8.</param>
        /// <param name="input">The input buffer.</param>
        /// <param name="inputOffset">The offset into the input buffer.</param>
        /// <param name="output">The output buffer.</param>
        /// <param name="outputOffset">The offset into the output buffer.</param>
        public static void Compute(int rounds,
                                   uint[] input, int inputOffset, uint[] output, int outputOffset)
        {
            if (rounds < 2 || rounds > 20 || (rounds & 1) == 1)
            {
                throw Exceptions.Argument("rounds", "Must be even and in the range 2 to 20.");
            }

            try
            {
                // .NET's bounds checking hurts performance in tight loops like this one.
                // So, I unroll the array to eliminate it - a 50% speed increase.
                uint x0 = input[inputOffset + 0];
                uint x1 = input[inputOffset + 1];
                uint x2 = input[inputOffset + 2];
                uint x3 = input[inputOffset + 3];
                uint x4 = input[inputOffset + 4];
                uint x5 = input[inputOffset + 5];
                uint x6 = input[inputOffset + 6];
                uint x7 = input[inputOffset + 7];
                uint x8 = input[inputOffset + 8];
                uint x9 = input[inputOffset + 9];
                uint x10 = input[inputOffset + 10];
                uint x11 = input[inputOffset + 11];
                uint x12 = input[inputOffset + 12];
                uint x13 = input[inputOffset + 13];
                uint x14 = input[inputOffset + 14];
                uint x15 = input[inputOffset + 15];

                for (int i = rounds; i > 0; i -= 2)
                {
                    x4 ^= R(x0 + x12, 7); x8 ^= R(x4 + x0, 9);
                    x12 ^= R(x8 + x4, 13); x0 ^= R(x12 + x8, 18);
                    x9 ^= R(x5 + x1, 7); x13 ^= R(x9 + x5, 9);
                    x1 ^= R(x13 + x9, 13); x5 ^= R(x1 + x13, 18);
                    x14 ^= R(x10 + x6, 7); x2 ^= R(x14 + x10, 9);
                    x6 ^= R(x2 + x14, 13); x10 ^= R(x6 + x2, 18);
                    x3 ^= R(x15 + x11, 7); x7 ^= R(x3 + x15, 9);
                    x11 ^= R(x7 + x3, 13); x15 ^= R(x11 + x7, 18);
                    x1 ^= R(x0 + x3, 7); x2 ^= R(x1 + x0, 9);
                    x3 ^= R(x2 + x1, 13); x0 ^= R(x3 + x2, 18);
                    x6 ^= R(x5 + x4, 7); x7 ^= R(x6 + x5, 9);
                    x4 ^= R(x7 + x6, 13); x5 ^= R(x4 + x7, 18);
                    x11 ^= R(x10 + x9, 7); x8 ^= R(x11 + x10, 9);
                    x9 ^= R(x8 + x11, 13); x10 ^= R(x9 + x8, 18);
                    x12 ^= R(x15 + x14, 7); x13 ^= R(x12 + x15, 9);
                    x14 ^= R(x13 + x12, 13); x15 ^= R(x14 + x13, 18);
                }

                output[outputOffset + 0] = input[inputOffset + 0] + x0; x0 = 0;
                output[outputOffset + 1] = input[inputOffset + 1] + x1; x1 = 0;
                output[outputOffset + 2] = input[inputOffset + 2] + x2; x2 = 0;
                output[outputOffset + 3] = input[inputOffset + 3] + x3; x3 = 0;
                output[outputOffset + 4] = input[inputOffset + 4] + x4; x4 = 0;
                output[outputOffset + 5] = input[inputOffset + 5] + x5; x5 = 0;
                output[outputOffset + 6] = input[inputOffset + 6] + x6; x6 = 0;
                output[outputOffset + 7] = input[inputOffset + 7] + x7; x7 = 0;
                output[outputOffset + 8] = input[inputOffset + 8] + x8; x8 = 0;
                output[outputOffset + 9] = input[inputOffset + 9] + x9; x9 = 0;
                output[outputOffset + 10] = input[inputOffset + 10] + x10; x10 = 0;
                output[outputOffset + 11] = input[inputOffset + 11] + x11; x11 = 0;
                output[outputOffset + 12] = input[inputOffset + 12] + x12; x12 = 0;
                output[outputOffset + 13] = input[inputOffset + 13] + x13; x13 = 0;
                output[outputOffset + 14] = input[inputOffset + 14] + x14; x14 = 0;
                output[outputOffset + 15] = input[inputOffset + 15] + x15; x15 = 0;
            }
            catch (IndexOutOfRangeException)
            {
                // For speed, don't bounds-check until .NET throws from a bounds error.
                Check.Null("input", input); Check.Bounds("input", input, inputOffset, 16);
                Check.Null("output", output); Check.Bounds("output", output, outputOffset, 16);
                throw;
            }
        }
    }
#region License

/*
Illusory Studios C# Crypto Library (CryptSharp)
Copyright (c) 2011 James F. Bellinger <jfb@zer7.com>

Permission to use, copy, modify, and/or distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
*/

#endregion

namespace CryptSharp.SCryptSubset.PCL
{
    using System;

    public static class Salsa20Core
    {
        /// <summary>
        /// Source Taken from: http://cr.yp.to/salsa20.html
        /// </summary>
        private static uint R(uint a, int b)
        {
            return (a << b) | (a >> (32 - b));
        }

        public static void Compute(int rounds,
                                   uint[] input, int inputOffset, uint[] output, int outputOffset,
                                   uint[] x)
        {
            if (rounds < 1 || rounds > 20 || (rounds & 1) == 1)
            {
                throw new ArgumentOutOfRangeException("rounds");
            }

            try
            {
                int i;
                for (i = 0; i < 16; i++)
                {
                    x[i] = input[i + inputOffset];
                }
                for (i = rounds; i > 0; i -= 2)
                {
                    x[4] ^= R(x[0] + x[12], 7);
                    x[8] ^= R(x[4] + x[0], 9);
                    x[12] ^= R(x[8] + x[4], 13);
                    x[0] ^= R(x[12] + x[8], 18);
                    x[9] ^= R(x[5] + x[1], 7);
                    x[13] ^= R(x[9] + x[5], 9);
                    x[1] ^= R(x[13] + x[9], 13);
                    x[5] ^= R(x[1] + x[13], 18);
                    x[14] ^= R(x[10] + x[6], 7);
                    x[2] ^= R(x[14] + x[10], 9);
                    x[6] ^= R(x[2] + x[14], 13);
                    x[10] ^= R(x[6] + x[2], 18);
                    x[3] ^= R(x[15] + x[11], 7);
                    x[7] ^= R(x[3] + x[15], 9);
                    x[11] ^= R(x[7] + x[3], 13);
                    x[15] ^= R(x[11] + x[7], 18);
                    x[1] ^= R(x[0] + x[3], 7);
                    x[2] ^= R(x[1] + x[0], 9);
                    x[3] ^= R(x[2] + x[1], 13);
                    x[0] ^= R(x[3] + x[2], 18);
                    x[6] ^= R(x[5] + x[4], 7);
                    x[7] ^= R(x[6] + x[5], 9);
                    x[4] ^= R(x[7] + x[6], 13);
                    x[5] ^= R(x[4] + x[7], 18);
                    x[11] ^= R(x[10] + x[9], 7);
                    x[8] ^= R(x[11] + x[10], 9);
                    x[9] ^= R(x[8] + x[11], 13);
                    x[10] ^= R(x[9] + x[8], 18);
                    x[12] ^= R(x[15] + x[14], 7);
                    x[13] ^= R(x[12] + x[15], 9);
                    x[14] ^= R(x[13] + x[12], 13);
                    x[15] ^= R(x[14] + x[13], 18);
                }
                for (i = 0; i < 16; i++)
                {
                    output[i + outputOffset] = x[i] + input[i + inputOffset];
                }
            }
            catch
            {
                Helper.CheckNull("input", input);
                Helper.CheckBounds("input", input, inputOffset, 16);
                Helper.CheckNull("output", output);
                Helper.CheckBounds("output", output, outputOffset, 16);
                Helper.CheckNull("x", x);
                Helper.CheckBounds("x", x, 0, 16);
                throw;
            }
        }
    }
}
}
