package huahua.service;

import huahua.core.CoreMethodAdapter;
import org.apache.log4j.Logger;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import java.util.Map;

public class BcelShellMethodAdapter extends CoreMethodAdapter<String> {
    private Logger logger = Logger.getLogger(BcelShellMethodAdapter.class);

    private final int access;
    private final String desc;
    private final Map<String, Object> analysisData;

    public BcelShellMethodAdapter(int api, MethodVisitor mv, String owner,
                                  int access, String name, String desc,
                                  String signature, String[] exceptions,
                                  Map<String, Object> analysisData) {
        super(api, mv, owner, access, name, desc, signature, exceptions);
        this.access = access;
        this.desc = desc;
        this.analysisData = analysisData;
    }

    @Override
    public void visitLdcInsn(Object cst) {
        if (cst instanceof String) {
            if (((String) cst).startsWith("$$BCEL$$$")) {
                this.analysisData.put("bcel-bytecode", cst);
                logger.info("find BCEL bytecode");
                super.visitLdcInsn(cst);
                operandStack.get(0).add("bcel-bytecode");
                return;
            }
        }
        super.visitLdcInsn(cst);
    }

    @Override
    public void visitMethodInsn(int opcode, String owner, String name, String desc, boolean itf) {
        boolean bcelInit = owner.equals("com/sun/org/apache/bcel/internal/util/ClassLoader") &&
                name.equals("<init>") && desc.equals("()V") && opcode == Opcodes.INVOKESPECIAL;
        boolean bcelLoadClass = owner.equals("com/sun/org/apache/bcel/internal/util/ClassLoader") &&
                name.equals("loadClass") && desc.equals("(Ljava/lang/String;)Ljava/lang/Class;")
                && opcode == Opcodes.INVOKEVIRTUAL;
        if (bcelInit) {
            logger.info("new BCEL ClassLoader");
            super.visitMethodInsn(opcode, owner, name, desc, itf);
            operandStack.get(0).add("new-bcel-classloader");
            return;
        }
        if (bcelLoadClass) {
            logger.info("BCEL ClassLoader loadClass method invoked");
            if (operandStack.get(0).contains("bcel-bytecode")) {
                logger.info("use found bytecode");
                this.analysisData.put("load-bcel", true);
            }
            super.visitMethodInsn(opcode, owner, name, desc, itf);
            return;
        }
        super.visitMethodInsn(opcode, owner, name, desc, itf);
    }
}
