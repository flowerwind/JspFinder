package huahua.Discovery;

import huahua.Constant.Constant;
import huahua.core.CoreMethodAdapter;
import huahua.data.MethodReference;
import org.apache.log4j.Logger;
import org.objectweb.asm.*;
import org.objectweb.asm.commons.JSRInlinerAdapter;
import org.omg.PortableInterceptor.INACTIVE;

import java.io.IOException;
import java.util.*;

public class FindEvilDiscovery {
    private static final Logger logger = Logger.getLogger(FindEvilDiscovery.class);

    public void discover() {
        findEvilDataflow();
    }

    private void findEvilDataflow() {
        final Map<MethodReference.Handle, Map<String,Set<Integer>>> EvilDataflow = new HashMap<>();
            for (MethodReference.Handle methodToVisit : Constant.sortedMethodCalls) {
                String className=methodToVisit.getOwner().substring(methodToVisit.getOwner().lastIndexOf("/")+1);
                byte[] classByte=Constant.classNameToByte.get(className);
                ClassReader cr = new ClassReader(classByte);
                FindEvilDataflowClassVisitor findEvilDataflowClassVisitor = new FindEvilDataflowClassVisitor(EvilDataflow, Opcodes.ASM6, methodToVisit, Constant.classNameToClassFileName.get(className));
                cr.accept(findEvilDataflowClassVisitor, ClassReader.EXPAND_FRAMES);
            }


    }

    private class FindEvilDataflowClassVisitor extends ClassVisitor {
        private FindEvilDataflowMethodVisitor findEvilDataflowMethodVisitor;
        private final Map<MethodReference.Handle, Map<String,Set<Integer>>> EvilDataflow;
        private final MethodReference.Handle methodToVisit;
        private String name;
        private String classFileName;
        private Set printEvilMessage = new HashSet();

        public FindEvilDataflowClassVisitor(Map<MethodReference.Handle, Map<String,Set<Integer>>> EvilDataflow, int api, MethodReference.Handle methodToVisit, String classFileName) {
            super(api);
            this.EvilDataflow = EvilDataflow;
            this.methodToVisit = methodToVisit;
            this.classFileName = classFileName;
        }


        @Override
        public void visit(int version, int access, String name, String signature,
                          String superName, String[] interfaces) {
            super.visit(version, access, name, signature, superName, interfaces);
            this.name = name;
        }

        @Override
        public MethodVisitor visitMethod(int access, String name, String descriptor, String signature, String[] exceptions) {
            //???method????????????
            MethodVisitor mv = super.visitMethod(access, name, descriptor, signature, exceptions);
            if (name.equals(this.methodToVisit.getName())) {
                if (Constant.debug) {
                    logger.info("???????????????:" + this.name + "     ??????????????????:" + name);
                }
                findEvilDataflowMethodVisitor = new FindEvilDataflowMethodVisitor(EvilDataflow, Opcodes.ASM6, access, descriptor, mv, this.name, name, signature, exceptions, classFileName, printEvilMessage);
                EvilDataflow.put(new MethodReference.Handle(this.name, name, descriptor), getReturnTaint());
                return new JSRInlinerAdapter(findEvilDataflowMethodVisitor, access, name, descriptor, signature, exceptions);
            }
            return super.visitMethod(access, name, descriptor, signature, exceptions);
        }

        public Map<String,Set<Integer>> getReturnTaint() {
            if (findEvilDataflowMethodVisitor == null) {
                throw new IllegalStateException("Never constructed the passthroughDataflowmethodVisitor!");
            }
            return findEvilDataflowMethodVisitor.toEvilTaint;
        }
    }

    private class FindEvilDataflowMethodVisitor extends CoreMethodAdapter {
        private final Map<String,Set<Integer>> toEvilTaint;//????????????????????????,key????????????????????????????????????:Runtime/ProcessBuilder/Behinder
        private final Map<MethodReference.Handle, Map<String,Set<Integer>>> EvilDataflow;
        private final int access;
        private final String desc;
        private final String owner;
        private final String name;
        private final boolean isStatic;
        private String classFileName;
        private Set printEvilMessage;

        public FindEvilDataflowMethodVisitor(Map<MethodReference.Handle, Map<String,Set<Integer>>> EvilDataflow, int api, int access, String desc, MethodVisitor mv, String owner, String name, String signature, String[] exceptions, String classFileName, Set printEvilMessage) {
            super(api, mv, owner, access, name, desc, signature, exceptions);
            this.EvilDataflow = EvilDataflow;
            this.toEvilTaint = new HashMap<>();
            this.access = access;
            this.desc = desc;
            this.owner = owner;
            this.name = name;
            this.isStatic = (access & Opcodes.ACC_STATIC) != 0;
            this.classFileName = classFileName;
            this.printEvilMessage = printEvilMessage;
        }

        @Override
        public void visitCode() {
            super.visitCode();

            int localIndex = 0;
            int argIndex = 0;
            if ((this.access & Opcodes.ACC_STATIC) == 0) {
                //????????????????????????????????????????????????????????????this
                //??????????????????????????????
                setLocalTaint(localIndex, argIndex);
                localIndex += 1;
                argIndex += 1;
            }
            for (Type argType : Type.getArgumentTypes(desc)) {
                //??????????????????????????????????????????????????????????????????
                setLocalTaint(localIndex, argIndex);
                localIndex += argType.getSize();
                argIndex += 1;
            }
        }

        @Override
        public void visitMethodInsn(int opcode, String owner, String name, String desc, boolean itf) {
            Type[] argTypes = Type.getArgumentTypes(desc);
            //???????????????????????????
            int retSize = Type.getReturnType(desc).getSize();
            Set<Integer> resultTaint;
            //?????????????????????????????????????????????????????????
            if (opcode != Opcodes.INVOKESTATIC) {
                Type[] extendedArgTypes = new Type[argTypes.length + 1];
                System.arraycopy(argTypes, 0, extendedArgTypes, 1, argTypes.length);
                extendedArgTypes[0] = Type.getObjectType(owner);
                argTypes = extendedArgTypes;
            }
            final List<Set<Integer>> argTaint = new ArrayList<Set<Integer>>(argTypes.length);
            switch (opcode) {
                case Opcodes.INVOKESTATIC:
                case Opcodes.INVOKEINTERFACE:
                case Opcodes.INVOKEVIRTUAL:
                case Opcodes.INVOKESPECIAL:
                    //todo ?????????????????????????????????
                    for (int i = 0; i < argTypes.length; i++) {
                        argTaint.add(null);
                    }

                    int stackIndex = 0;
                    for (int i = 0; i < argTypes.length; i++) {
                        Type argType = argTypes[i];
                        if (argType.getSize() > 0) {
                            //?????????????????????????????????????????????
                            argTaint.set(argTypes.length - 1 - i, operandStack.get(stackIndex + argType.getSize() - 1));
                        }
                        stackIndex += argType.getSize();
                    }

                    // ????????????????????????????????????0?????????????????????
                    if (name.equals("<init>")) {
                        // Pass result taint through to original taint set; the initialized object is directly tainted by
                        // parameters
                        resultTaint = argTaint.get(0);
                    } else {
                        resultTaint = new HashSet<>();
                    }

                    //????????????PassthroughDiscovery??????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????
                    Set<Integer> passthrough = Constant.passthroughDataflow.get(new MethodReference.Handle(owner, name, desc));
                    if (passthrough != null && passthrough.size() > 0) {
                        for (Integer passthroughDataflowArg : passthrough) {
                            resultTaint.addAll(argTaint.get(new Integer(passthroughDataflowArg)));
                        }
                    }

                    // ???????????????????????????????????????????????????visit??????????????????????????????????????????visit?????????
                    Map<String,Set<Integer>> evilMethodDataflow = EvilDataflow.get(new MethodReference.Handle(owner, name, desc));
                    if (evilMethodDataflow != null && evilMethodDataflow.size() > 0) {
                        for(String evilType:evilMethodDataflow.keySet()){
                            Set<Integer> taints=new HashSet<>();
                            Set<Integer> evilMethodDataflowArgList=evilMethodDataflow.get(evilType);
                            if (evilMethodDataflowArgList!=null && evilMethodDataflowArgList.size()>0){
                                for (Integer evilMethodDataflowArg : evilMethodDataflowArgList) {
                                    //??????argTaint.get(new Integer(evilMethodDataflowArg))??????????????????????????????????????????????????????
                                    Set<Integer> tmpTaints=argTaint.get(evilMethodDataflowArg);
                                    taints.addAll(tmpTaints);
                                }
                            }
                            toEvilTaint.put(evilType,taints);
                        }
                        //????????????0????????????????????????????????????????????????
                        if (toEvilTaint.size() > 0) {
                            for(String evilType:toEvilTaint.keySet()){
                                Set<Integer> tains=toEvilTaint.get(evilType);
                                // ?????????????????????_jspService??????????????????????????????(request?????????_jspService??????????????????????????????????????????request??????--????????????????????????)
                                if (this.name.equals("_jspService") && tains.contains(1)) {
                                    //printEvilMessage???????????????1????????????????????????????????????webshell??????????????????????????????????????????1??????????????????????????????????????????
                                    if (!printEvilMessage.contains(1)) {
                                        printEvilMessage.add(1);
                                        String msg;
                                        if(evilType.equals("Behinder")){
                                            msg=Constant.classNameToJspName.get(classFileName)+"------?????????????????????ClassLoader.defineClass??????request?????????????????????/?????????/??????webshell";
                                        }else{
                                            msg=Constant.classNameToJspName.get(classFileName) + "   "+evilType+"??????request?????????????????????webshell!!!";
                                        }
                                        logger.info(msg);
                                        Constant.evilClass.add(classFileName);
                                        Constant.msgList.add(msg);
                                    }
                                }
                                if (Constant.debug) {
                                    logger.info("???:" + this.owner + "??????:" + this.name + "????????????????????????:" + name);
                                    logger.info("????????????:" + tains);
                                }
                            }
                        }
                    }
                    break;
                default:
                    throw new IllegalStateException("Unexpected value: " + opcode);
            }

            //??????????????????
            if(opcode == Opcodes.INVOKEINTERFACE){
                boolean scriptEngineEval=owner.equals("javax/script/ScriptEngine") && name.equals("eval");
                boolean scriptEnginePut=owner.equals("javax/script/ScriptEngine") && name.equals("put");
                if(scriptEngineEval){
                    Set taintList=argTaint.get(1);
                    Set tmpTaintList=new HashSet();
                    for (Object taint:taintList){
                        if(taint instanceof Integer){
                            if (!printEvilMessage.contains(1)) {
                                printEvilMessage.add(1);
                                String msg=Constant.classNameToJspName.get(classFileName) + "------ScriptEngine??????request?????????????????????webshell!!!";
                                logger.info(msg);
                                Constant.evilClass.add(classFileName);
                                Constant.msgList.add(msg);
                            }
                            tmpTaintList.add(taint);
                        }
                    }
                    toEvilTaint.put("ScriptEngine",tmpTaintList);
                }

                if(scriptEnginePut){
                    Set taintList=argTaint.get(2);
                    Set tmpTaintList=new HashSet();
                    for (Object taint:taintList){
                        if(taint instanceof Integer){
                            if (!printEvilMessage.contains(1)) {
                                printEvilMessage.add(1);
                                String msg=Constant.classNameToJspName.get(classFileName) + "------ScriptEngine??????request?????????????????????webshell!!!";
                                logger.info(msg);
                                Constant.evilClass.add(classFileName);
                                Constant.msgList.add(msg);
                            }
                            tmpTaintList.add(taint);
                        }
                    }
                    toEvilTaint.put("ScriptEngine",tmpTaintList);
                }
            }
            //??????????????????
            if (opcode == Opcodes.INVOKEVIRTUAL) {
                //????????????bool????????????Runtime exc?????????????????????????????????????????????????????????????????????????????????????????????????????????????????????(??????????????????????????????????????????????????????????????????????????????????????????append?????????????????????????????????)
                boolean subString = owner.equals("java/lang/String") && name.equals("substring");
                boolean classCallMethod = owner.equals("java/lang/Class") && (name.equals("getMethod") || name.equals("getConstructors") || name.equals("getConstructor") || name.equals("getDeclaredConstructors") || name.equals("getDeclaredConstructor") || name.equals("getDeclaredMethod"));
                boolean decodeBuffer = name.equals("decodeBuffer") && owner.equals("sun/misc/BASE64Decoder") && desc.equals("(Ljava/lang/String;)[B");
                boolean jdk8DecodeString= owner.equals("java/util/Base64$Decoder") && name.equals("decode") && desc.equals("(Ljava/lang/String;)[B");
                boolean jdk8DecodeBytes= owner.equals("java/util/Base64$Decoder") && name.equals("decode") && desc.equals("([B)[B");
                boolean exec = name.equals("exec") && owner.equals("java/lang/Runtime") & desc.contains("Ljava/lang/Process");     //???desc???????????????????????????Process???????????????Runtime.exec?????????????????????????????????????????????????????????
                boolean append = name.equals("append") &&
                        owner.equals("java/lang/StringBuilder") &&
                        desc.equals("(Ljava/lang/String;)Ljava/lang/StringBuilder;");
                boolean toString = name.equals("toString") && owner.equals("java/lang/StringBuilder") && desc.equals("()Ljava/lang/String;");
                //?????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????
                boolean inputStream=owner.equals("java/io/InputStream") && name.equals("read") && desc.equals("([BII)I");
                boolean methodInvoke=owner.equals("java/lang/reflect/Method") && name.equals("invoke") && desc.equals("(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;");
                if (subString) {
                    int k = 0;
                    Set listAll = new HashSet();
                    for (Type argType : Type.getArgumentTypes(desc)) {
                        int size = argType.getSize();
                        while (size-- > 0) {
                            Set taintList = operandStack.get(k);
                            if (taintList.size() > 0) {
                                listAll.addAll(taintList);
                            }
                            k++;
                        }
                    }
                    listAll.addAll(operandStack.get(k));
                    super.visitMethodInsn(opcode, owner, name, desc, itf);
                    operandStack.get(0).addAll(listAll);
                    return;
                }

//                //?????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????ProcessBuilder???Runtime???????????????
                if (classCallMethod) {
                    int k = 0;
//                    Set listAll =new HashSet();
                    for (Type argType : Type.getArgumentTypes(desc)) {
                        int size = argType.getSize();
                        while (size-- > 0) {
                            Set taintList = operandStack.get(k);
                            //??????????????????????????????????????? ?????????????????????????????????????????????
                            if (taintList.contains("java.lang.ProcessBuilder") || taintList.contains("java.lang.Runtime")) {
                                //????????????????????????????????????java.lang.ProcessBuilder??????java.lang.Runtime???????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????
                                if (!printEvilMessage.contains(1)) {
                                    printEvilMessage.add(1);
                                    String msg=Constant.classNameToJspName.get(classFileName) + "------????????????ProcessBuilder???Runtime???????????????webshell";
                                    logger.info(msg);
                                    Constant.evilClass.add(classFileName);
                                    Constant.msgList.add(msg);
                                }
                            }
                            k++;
                        }
                    }
                    if (operandStack.get(k).contains("java.lang.ProcessBuilder") || operandStack.get(k).contains("java.lang.Runtime")) {
                        if (!printEvilMessage.contains(1)) {
                            printEvilMessage.add(1);
                            String msg=Constant.classNameToJspName.get(classFileName) + "------????????????ProcessBuilder???Runtime???????????????webshell";
                            logger.info(msg);
                            Constant.evilClass.add(classFileName);
                            Constant.msgList.add(msg);
                        }
                    }
                    super.visitMethodInsn(opcode, owner, name, desc, itf);
                    return;
                }
                if (decodeBuffer || jdk8DecodeString) {
                    String encodeString = "";
                    Set taintList = operandStack.get(0);
                    int taintNum = -1;
                    for (Object taint : taintList) {
                        taintNum++;
                        if (taint instanceof String) {
                            encodeString = (String) taint;
                            break;
                        } else if (taint instanceof Integer) {
                            super.visitMethodInsn(opcode, owner, name, desc, itf);
                            operandStack.get(0).addAll(taintList);
                            return;
                        }
                    }
                    if (encodeString.length() > 0) {
                        String decodeString = new String();
                        try {
                            decodeString = new String(new sun.misc.BASE64Decoder().decodeBuffer(encodeString));
                        } catch (IOException e) {
                            e.printStackTrace();
                        }
                        List newTaintList = (List) new ArrayList<>(taintList);
                        newTaintList.set(taintNum, decodeString);
                        super.visitMethodInsn(opcode, owner, name, desc, itf);
                        operandStack.get(0).addAll(newTaintList);
                        return;
                    }
                }
                if(jdk8DecodeBytes){
                    Set taintList = operandStack.get(0);
                    for (Object taint : operandStack.get(0)) {
                        //??????Opcodes.BIPUSH???????????????byte????????????????????????????????????new String(byte[])??????????????????byte[]?????????String??????????????????
                        if (taint instanceof ArrayList) {
                            int len = ((ArrayList) taint).size();
                            byte[] tmp = new byte[len];
                            for (int i = 0; i < len; i++) {
                                tmp[i] = (byte) (int) (((ArrayList) taint).get(i));
                            }
                            super.visitMethodInsn(opcode, owner, name, desc, itf);
                            try {
                                operandStack.get(0).add(new String(new sun.misc.BASE64Decoder().decodeBuffer(new String(tmp))));
                            } catch (IOException e) {
                                e.printStackTrace();
                            }
                            return;
                        }
                        //???????????????arrayList???byte????????????????????????????????????
                        super.visitMethodInsn(opcode, owner, name, desc, itf);
                        operandStack.get(0).addAll(taintList);
                        return;
                    }
                }
                if (exec) {
                    if(operandStack.get(0).size()>0){
                        Set<Integer> taints=new HashSet<>();
                        for (Object node : operandStack.get(0)) {
                            if (node instanceof Integer) {
                                int taintNum = (Integer) node;
                                if (Constant.debug) {
                                    logger.info("Runtime.exec??????arg" + taintNum + "??????");
                                }
                                taints.add(taintNum);
                                if (this.name.equals("_jspService")) {
                                    if (!printEvilMessage.contains(1)) {
                                        printEvilMessage.add(1);
                                        String msg=Constant.classNameToJspName.get(classFileName) + "------Runtime.exec??????request?????????????????????webshell!!!";
                                        logger.info(msg);
                                        Constant.evilClass.add(classFileName);
                                        Constant.msgList.add(msg);
                                    }
                                }
                            }
                        }
                        //??????????????????Runtime.exec????????????????????????????????????
                        toEvilTaint.put("Runtime",taints);
                        super.visitMethodInsn(opcode, owner, name, desc, itf);
                        return;
                    }
                }
                if (append && (operandStack.get(0).size() > 0 || operandStack.get(1).size() > 0)) {
                    Set taintList1 = operandStack.get(0);
                    Set taintList2 = operandStack.get(1);
                    super.visitMethodInsn(opcode, owner, name, desc, itf);
                    if (taintList1.size() > 0) {
                        operandStack.get(0).addAll(taintList1);
                    }
                    if (taintList2.size() > 0) {
                        operandStack.get(0).addAll(taintList2);
                    }
                    return;
                }
                if (toString && operandStack.get(0).size() > 0) {
                    Set taintList = operandStack.get(0);
                    super.visitMethodInsn(opcode, owner, name, desc, itf);
                    operandStack.get(0).addAll(taintList);
                    return;
                }

                if(inputStream){
                    Type[] argumentTypes=Type.getArgumentTypes(desc);
                    //operandStack.get(argumentTypes.length)?????????????????????????????????
                    Set tains=operandStack.get(argumentTypes.length);
                    if(tains.size()>0){
                        Set tmpTaints=operandStack.get(argumentTypes.length-1);
                        for(Object tmpTaint:tmpTaints){
                            if(tmpTaint instanceof String && ((String)tmpTaint).indexOf("instruction")>-1){
                                String localVariablesNum=((String) tmpTaint).substring(11);
                                localVariables.get(new Integer(localVariablesNum)).addAll(tains);
                            }
                        }
                    }
                }

                if(methodInvoke){
                    //????????????method?????????????????????
                    Set taints=argTaint.get(0);
                    if(taints.size()>0){
                        for(Object taint:taints){
                            if(taint instanceof String && ((String)taint).equals("defineClass")){
                                //????????????????????????????????????invoke??????????????????
                                Set tmpTaints=argTaint.get(2);
                                Set<Integer> numTains=new HashSet<>();
                                for(Object tmpTaint:tmpTaints){
                                    //???????????????????????????defineClass???????????????
                                    if (tmpTaint instanceof Integer){
                                        if (!printEvilMessage.contains(1)) {
                                            printEvilMessage.add(1);
                                            String msg=Constant.classNameToJspName.get(classFileName) + "------defineClass????????????????????????????????????request???????????????????????????/?????????/????????????webshell";
                                            logger.info(msg);
                                            Constant.evilClass.add(classFileName);
                                            Constant.msgList.add(msg);
                                        }
                                        numTains.add((Integer) tmpTaint);
                                    }
                                }
                                toEvilTaint.put("Behinder",numTains);
                            }
                        }
                    }
                }
            }
            //??????????????????
            if (opcode == Opcodes.INVOKESPECIAL) {
                //??????ProcessBuilder,??????????????????????????????????????????
                boolean processBuilderInit = owner.equals("java/lang/ProcessBuilder") && name.equals("<init>");
                boolean stringByteInit = owner.equals("java/lang/String") && name.equals("<init>") && (desc.equals("([B)V") || desc.equals("([BLjava/lang/String;)V"));
                boolean stringInit = owner.equals("java/lang/String") && name.equals("<init>");
                boolean stringBuilderInit = owner.equals("java/lang/StringBuilder") && name.equals("<init>") && desc.equals("(Ljava/lang/String;)V");
                boolean defineClass=owner.equals("java/lang/ClassLoader") && name.equals("defineClass");
                if (stringByteInit) {
                    Set taintList = operandStack.get(0);
                    for (Object taint : operandStack.get(0)) {
                        //??????Opcodes.BIPUSH???????????????byte????????????????????????????????????new String(byte[])??????????????????byte[]?????????String??????????????????
                        if (taint instanceof ArrayList) {
                            int len = ((ArrayList) taint).size();
                            byte[] tmp = new byte[len];
                            for (int i = 0; i < len; i++) {
                                tmp[i] = (byte) (int) (((ArrayList) taint).get(i));
                            }
                            super.visitMethodInsn(opcode, owner, name, desc, itf);
                            operandStack.get(0).add(new String(tmp));
                            return;
                        }
                        //???????????????arrayList???byte????????????????????????????????????
                        super.visitMethodInsn(opcode, owner, name, desc, itf);
                        operandStack.get(0).addAll(taintList);
                        return;
                    }
                }
                if (stringInit) {
                    //??????String??????????????????????????????????????????
                    int k = 0;
                    Set listAll = new HashSet();
                    for (Type argType : Type.getArgumentTypes(desc)) {
                        int size = argType.getSize();
                        while (size-- > 0) {
                            Set taintList = operandStack.get(k);
                            if (taintList.size() > 0) {
                                listAll.addAll(taintList);
                            }
                            k++;
                        }
                    }
                    super.visitMethodInsn(opcode, owner, name, desc, itf);
                    operandStack.get(0).addAll(listAll);
                    return;
                }
                if (processBuilderInit) {
                    if(operandStack.get(0).size()>0){
                        Set<Integer> taints=new HashSet<>();
                        for (Object node : operandStack.get(0)) {
                            if (node instanceof Integer) {
                                int taintNum = (Integer) node;
                                if (Constant.debug) {
                                    logger.info("ProcessBuilder??????arg" + taintNum + "??????");
                                }
                                taints.add(taintNum);
                                if (this.name.equals("_jspService")) {
                                    if (!printEvilMessage.contains(1)) {
                                        printEvilMessage.add(1);
                                        String msg=Constant.classNameToJspName.get(classFileName) + "   ProcessBuilder??????request?????????????????????webshell!!!";
                                        logger.info(msg);
                                        Constant.evilClass.add(classFileName);
                                        Constant.msgList.add(msg);
                                    }
                                }
                            }
                        }
                        toEvilTaint.put("ProcessBuilder",taints);
                        super.visitMethodInsn(opcode, owner, name, desc, itf);
                        return;
                    }
                }

                if (stringBuilderInit && operandStack.get(0).size() > 0) {
                    Set taintList = operandStack.get(0);
                    super.visitMethodInsn(opcode, owner, name, desc, itf);
                    operandStack.get(0).addAll(taintList);
                    return;
                }

                //????????????????????????defineClass????????????1??????????????????1??????????????????????????????????????????????????????
                if(defineClass){
                    Type[] argumentTypes=Type.getArgumentTypes(desc);
                    //operandStack.get(argumentTypes.length-1)????????????defineClass???1????????????????????????
                    if(operandStack.get(argumentTypes.length-1).size()>0){
                        Set<Integer> taints=new HashSet<>();
                        for (Object node : operandStack.get(argumentTypes.length-1)) {
                            if (node instanceof Integer) {
                                int taintNum = (Integer) node;
                                if (Constant.debug) {
                                    logger.info("ClassLoader???defineClass??????arg" + taintNum + "??????");
                                }
                                taints.add(taintNum);
                                if (this.name.equals("_jspService")) {
                                    if (!printEvilMessage.contains(1)) {
                                        printEvilMessage.add(1);
                                        String msg=Constant.classNameToJspName.get(classFileName) + "------ClassLoader???defineClass??????request??????????????????????????????webshell(?????????)!!!";
                                        logger.info(msg);
                                        Constant.evilClass.add(classFileName);
                                        Constant.msgList.add(msg);
                                    }
                                }
                            }
                        }
                        toEvilTaint.put("Behinder",taints);
                        super.visitMethodInsn(opcode, owner, name, desc, itf);
                        return;
                    }
                }
            }
            if (opcode == Opcodes.INVOKESTATIC) {
                boolean isValueOf = name.equals("valueOf") && desc.equals("(Ljava/lang/Object;)Ljava/lang/String;") && owner.equals("java/lang/String");
                if (isValueOf && operandStack.get(0).size() > 0) {
                    Set taintList = operandStack.get(0);
                    super.visitMethodInsn(opcode, owner, name, desc, itf);
                    operandStack.get(0).addAll(taintList);
                    return;
                }
            }

            super.visitMethodInsn(opcode, owner, name, desc, itf);
            //????????????????????????????????????????????????
            if (retSize > 0) {
                operandStack.get(retSize - 1).addAll(resultTaint);
            }
        }

        @Override
        public void visitIntInsn(int opcode, int operand) {
            if (opcode == Opcodes.BIPUSH) {
                super.visitIntInsn(opcode, operand);
                operandStack.get(0).add(operand);
                return;
            }
            super.visitIntInsn(opcode, operand);
        }


        @Override
        public void visitInsn(int opcode) {
            if (opcode == Opcodes.AASTORE) {
                Set taintList = operandStack.get(0);
                if (taintList.size() > 0) {
                    super.visitInsn(opcode);
                    // ?????????????????????????????????????????????p[i]="456"+p[i]+"123"????????????????????????aastore?????????????????????????????????????????????super.visitInsn(Opcodes.AASTORE)????????????????????????????????? operandStack.get(0)?????????
                    if (operandStack.size() > 0) {
                        operandStack.get(0).addAll(taintList);
                    }
                    return;
                }
            }
            if (opcode == Opcodes.BASTORE) {
                Set taintList = operandStack.get(0);
                super.visitInsn(opcode);
                if (taintList.size() > 0) {
                    for (Object tmpObj : operandStack.get(0)) {
                        if (tmpObj instanceof ArrayList) {
                            ((ArrayList) tmpObj).addAll(taintList);
                            return;
                        }
                    }
                    ArrayList list = new ArrayList<>();
                    list.addAll(taintList);
                    operandStack.set(0, list);
                }
                return;
            }
            if (opcode == Opcodes.AALOAD) {
                //operandStack.get(1)???????????????
                Set taintList = operandStack.get(1);
                super.visitInsn(opcode);
                if (taintList.size() > 0) {
                    operandStack.get(0).addAll(taintList);
                }
                return;
            }
            super.visitInsn(opcode);
        }

        @Override
        public void visitLdcInsn(Object cst) {
            if (cst instanceof String) {
                super.visitLdcInsn(cst);
                operandStack.get(0).add(cst);
                return;
            }
            super.visitLdcInsn(cst);
        }
    }

}
