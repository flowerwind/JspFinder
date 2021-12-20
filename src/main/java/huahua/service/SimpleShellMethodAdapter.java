package huahua.service;

import huahua.core.CoreMethodAdapter;
import org.apache.log4j.Logger;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;


import java.util.Map;

public class SimpleShellMethodAdapter extends CoreMethodAdapter<String> {
    private Logger logger = Logger.getLogger(BcelShellMethodAdapter.class);

    private final int access;
    private final String desc;
    private final Map<String, Object> analysisData;

    public SimpleShellMethodAdapter(int api, MethodVisitor mv, String owner,
                                    int access, String name, String desc,
                                    String signature, String[] exceptions,
                                    Map<String, Object> analysisData) {
        super(api, mv, owner, access, name, desc, signature, exceptions);
        this.access = access;
        this.desc = desc;
        this.analysisData = analysisData;
    }

    @Override
    public void visitCode() {
        super.visitCode();
        if (localVariables.size() > 1) {
            for (int i = 1; i < localVariables.size(); i++) {
                logger.info("set param index:" + i + " is taint");
                localVariables.get(i).add("taint");
            }
        }
    }

    @Override
    public void visitMethodInsn(int opcode, String owner, String name, String desc, boolean itf) {
        boolean getRuntimeExpr = owner.equals("java/lang/Runtime") &&
                name.equals("getRuntime") && desc.equals("()Ljava/lang/Runtime;") &&
                opcode == Opcodes.INVOKESTATIC;
        boolean execExpr = owner.equals("java/lang/Runtime") &&
                name.equals("exec") && desc.equals("(Ljava/lang/String;)Ljava/lang/Process;") &&
                opcode == Opcodes.INVOKEVIRTUAL;
        if (getRuntimeExpr) {
            super.visitMethodInsn(opcode, owner, name, desc, itf);
            operandStack.get(0).add("runtime");
            return;
        }
        if (execExpr) {
            if (operandStack.get(1).contains("runtime")) {
                logger.info("Runtime.exec method invoked");
                if (operandStack.get(0).contains("taint")) {
                    logger.info("find BCEL webshell");
                    super.visitMethodInsn(opcode, owner, name, desc, itf);
                    return;
                }
            }
        }
        super.visitMethodInsn(opcode, owner, name, desc, itf);
    }
}
