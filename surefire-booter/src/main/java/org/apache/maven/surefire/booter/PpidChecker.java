package org.apache.maven.surefire.booter;

/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.lang.management.ManagementFactory;
import java.util.Locale;
import java.util.StringTokenizer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Recognizes PPID.
 *
 * @since 2.20.1
 */
final class PpidChecker
{
    private static final String WMIC_PPID = "ParentProcessId";

    private static final String WMIC_CREATION_DATE = "CreationDate";

    private static final String WINDOWS_CMD =
            "wmic process where (ProcessId=%d) get " + WMIC_CREATION_DATE + ", " + WMIC_PPID;

    private static final String UNIX_CMD = "ps -o etime -p %s";

    private static final Pattern UNIX_CMD_OUT_PATTERN =
            Pattern.compile( "^((([\\d]+)-)?([\\d]{2}))?[:]?([\\d]{2}):([\\d]{2})$" );

    private static long fromDays( Matcher matcher ) {
        String s = matcher.group( 3 );
        return s == null ? 0L : 24L * 60L * 60L * Byte.parseByte( s );
    }

    private static long fromHours( Matcher matcher ) {
        String s = matcher.group( 4 );
        return s == null ? 0L : 60L * 60L * Byte.parseByte( s );
    }

    private static long fromMinutes( Matcher matcher ) {
        String s = matcher.group( 5 );
        return s == null ? 0L : 60L * Byte.parseByte( s );
    }

    private static long fromSeconds( Matcher matcher ) {
        String s = matcher.group( 6 );
        return s == null ? 0L : Byte.parseByte( s );
    }

    // http://manpages.ubuntu.com/manpages/precise/en/man1/ps.1.html
    // https://www.freebsd.org/cgi/man.cgi?query=ps&manpath=SuSE+Linux/i386+11.3

    // http://manpages.ubuntu.com/manpages/xenial/man1/ps.1.html
    // etime       ELAPSED   elapsed time since the process was started, in
    //             the form [[DD-]hh:]mm:ss.

    static void unix() throws IOException, InterruptedException
    {
        String ppid = System.getProperty( "surefire.ppid" );
        String[] cmd = { "/bin/sh", "-c", String.format( Locale.ROOT, UNIX_CMD, ppid ) };
        ProcessBuilder probuilder = new ProcessBuilder( cmd );
        Process p = probuilder.start();
        BufferedReader reader = new BufferedReader( new InputStreamReader( p.getInputStream() ) );
        for ( String line = reader.readLine(); line != null; line = reader.readLine() )
        {
            System.out.println(line);
            line = line.trim();
            if ( !line.isEmpty() )
            {
                Matcher matcher = UNIX_CMD_OUT_PATTERN.matcher( line );
                if (matcher.matches()) {
                    long pidUptime = (long) Math.floor( ManagementFactory.getRuntimeMXBean().getUptime() / 1000d );
                    long ppidUptime = fromDays( matcher )
                                              + fromHours( matcher )
                                              + fromMinutes( matcher )
                                              + fromSeconds( matcher );
                    System.out.printf( "%d %d\n", pidUptime, ppidUptime);
                    break;
                }
            }
        }
        reader.close();
        p.waitFor();
        p.destroy();
    }

    static void windows() throws IOException, InterruptedException
    {
        final long pid;
        String processName = ManagementFactory.getRuntimeMXBean().getName();
        if ( processName != null && processName.contains( "@" ) )
        {
            try
            {
                pid = Long.parseLong( processName.substring( 0, processName.indexOf( '@' ) ) );
            }
            catch ( NumberFormatException e )
            {
                return;
            }
        }
        else
        {
            return;
        }

        String[] cmd = { "CMD", "/A/C", String.format( Locale.ROOT, WINDOWS_CMD, pid ) };
        ProcessBuilder probuilder = new ProcessBuilder( cmd );
        Process p = probuilder.start();
        BufferedReader reader = new BufferedReader( new InputStreamReader( p.getInputStream() ) );
        boolean hasHeader = false;
        boolean isStartTimestampFirst = false;
        String startTimestamp = null;
        long ppid = 0;
        for ( String line = reader.readLine(); line != null; line = reader.readLine() )
        {
            line = line.trim();

            if ( line.isEmpty() )
            {
                continue;
            }

            if ( hasHeader )
            {
                StringTokenizer args = new StringTokenizer( line );
                if ( args.countTokens() == 2 )
                {
                    if ( isStartTimestampFirst )
                    {
                        startTimestamp = args.nextToken();
                        ppid = Long.parseLong( args.nextToken() );
                    }
                    else
                    {
                        startTimestamp = args.nextToken();
                        ppid = Long.parseLong( args.nextToken() );
                    }
                }
            }
            else
            {
                StringTokenizer args = new StringTokenizer( line );
                if ( args.countTokens() == 2 )
                {
                    String arg0 = args.nextToken();
                    String arg1 = args.nextToken();
                    isStartTimestampFirst = WMIC_CREATION_DATE.equals( arg0 );
                    hasHeader = isStartTimestampFirst || WMIC_PPID.equals( arg0 );
                    hasHeader &= WMIC_CREATION_DATE.equals( arg1 ) || WMIC_PPID.equals( arg1 );
                }
            }
        }
        reader.close();
        p.waitFor();
        p.destroy();
    }
}
