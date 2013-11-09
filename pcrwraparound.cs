/*****************************************************************************
 * License: GNU GPLv2
 *****************************************************************************/

using System;
using System.IO;

class pcrwraparound
{
    public static void Main(string[] args)
    {

        if (args.Length == 0)
        {
            Console.WriteLine("pcrwraparound in.ts");
            Environment.Exit(0);
        }

        FileStream reader = null;

        try
        {
            reader = new FileStream(args[0], FileMode.Open, FileAccess.Read);

            // detect packet size
            int packet_size = 188;
            {
                byte[] buf = new byte[192 * 4];
                reader.Seek(0, SeekOrigin.Begin);
                if (reader.Read(buf, 0, 192 * 4) != (192 * 4))
                {
                    throw new Exception();
                }
                if ((buf[188 * 0] == 0x47) && (buf[188 * 1] == 0x47) && (buf[188 * 2] == 0x47) && (buf[188 * 3] == 0x47))
                {
                    packet_size = 188;
                }
                else if ((buf[192 * 0 + 4] == 0x47) && (buf[192 * 1 + 4] == 0x47) && (buf[192 * 2 + 4] == 0x47) && (buf[192 * 3 + 4] == 0x47))
                {
                    packet_size = 192;
                }
                else
                {
                    throw new Exception();
                }
            }

            // find first pcr
            ulong first_pcr = ulong.MaxValue;
            reader.Seek(0, SeekOrigin.Begin);
            while (true) {
                byte[] buf = new byte[packet_size];
                if (reader.Read(buf, 0, packet_size) != packet_size)
                {
                    break;
                }
                ulong pcr = get_pcr_base(buf, packet_size);
                if (pcr != ulong.MaxValue)
                {
                    first_pcr = pcr;
                    break;
                }
            }
            if (first_pcr == ulong.MaxValue) {
                throw new Exception();
            }

            // find final pcr
            ulong final_pcr = ulong.MaxValue;
            reader.Seek(packet_size * ((reader.Length / packet_size) - 1), SeekOrigin.Begin);
            while (true) {
                byte[] buf = new byte[packet_size];
                if (reader.Read(buf, 0, packet_size) != packet_size)
                {
                    break;
                }
                ulong pcr = get_pcr_base(buf, packet_size);
                if (pcr != ulong.MaxValue)
                {
                    final_pcr = pcr;
                    break;
                }
                reader.Seek(-packet_size * 2, SeekOrigin.Current);
            }
            if (final_pcr == ulong.MaxValue)
            {
                throw new Exception();
            }

            // detect pcr wraparound
            if (final_pcr < first_pcr)
            {
                Console.WriteLine("detected pcr wraparound");
            }
        }
        catch (Exception e)
        {
            Console.WriteLine(e);
        }
        finally
        {
            if (reader != null)
            {
                reader.Close();
            }
        }
    }

    static ulong get_pcr_base(byte[] buf, int packet_size)
    {
        ulong pcr_base = ulong.MaxValue;
        int i = 0;

        if (packet_size == 192)
        {
            i += 4;
        }

        bool sync_byte = (buf[i + 0] == 0x47);
        ushort pid = (ushort)((((ushort)(buf[i + 1] & 0x1F)) << 8) + buf[i + 2]);
        bool adaptation_field_indicator = ((buf[i + 3] & 0x20) == 0x20);
        i += 4;

        if (!sync_byte)
        {
            return ulong.MaxValue;
        }

        if (adaptation_field_indicator)
        {
            int adaptation_field_length = buf[i + 0];
            i += 1;

            if (adaptation_field_length > 183)
            {
                return ulong.MaxValue;
            }
            else if (adaptation_field_length > 0)
            {
                bool pcr_flag = ((buf[i + 0] & 0x10) == 0x10);
                i += 1;

                if (pcr_flag)
                {
                    if ((pid == 0x0000) || (pid == 0x0001) || ((0x0010 <= pid) && (pid <= 0x1FFE)))
                    {
                        pcr_base = (ulong)(((ulong)(buf[i + 0]       )) << 8 * 4 - 7) +
                                   (ulong)(((ulong)(buf[i + 1]       )) << 8 * 3 - 7) +
                                   (ulong)(((ulong)(buf[i + 2]       )) << 8 * 2 - 7) +
                                   (ulong)(((ulong)(buf[i + 3]       )) << 8 * 1 - 7) +
                                   (ulong)(((ulong)(buf[i + 4] & 0x80)) >>         7);
                    }
                }
            }
        }

        return pcr_base;
    }
}


