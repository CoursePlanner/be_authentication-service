package org.course_planner.authentication.filter;

import jakarta.servlet.ReadListener;
import jakarta.servlet.ServletInputStream;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;

public class ServletInputStreamWrapper extends ServletInputStream {
    private final InputStream inputStream;

    protected ServletInputStreamWrapper(byte[] body) {
        inputStream = new ByteArrayInputStream(body);
    }

    @Override
    public int read() throws IOException {
        return this.inputStream.read();
    }

    @Override
    public int readLine(byte[] b, int off, int len) throws IOException {
        return super.readLine(b, off, len);
    }

    @Override
    public boolean isFinished() {
        try {
            return inputStream.available() == 0;
        } catch (Exception e) {
            return false;
        }
    }

    @Override
    public boolean isReady() {
        return true;
    }

    @Override
    public void setReadListener(ReadListener readListener) {
        //
    }
}
