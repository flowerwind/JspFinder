package huahua.service;

import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.commons.JSRInlinerAdapter;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class ReflectionShellClassVisitor extends ClassVisitor {
    private Map<String, List<Boolean>> analysisData;

    private String name;
    private String signature;
    private String superName;
    private String[] interfaces;

    public ReflectionShellClassVisitor() {
        super(Opcodes.ASM8);
        this.analysisData = new HashMap<>();
    }

    public Map<String, List<Boolean>> getAnalysisData() {
        return analysisData;
    }


    @Override
    public void visit(int version, int access, String name, String signature,
                      String superName, String[] interfaces) {
        super.visit(version, access, name, signature, superName, interfaces);
        this.name = name;
        this.signature = signature;
        this.superName = superName;
        this.interfaces = interfaces;
    }

    @Override
    public MethodVisitor visitMethod(int access, String name, String descriptor,
                                     String signature, String[] exceptions) {
        MethodVisitor mv = super.visitMethod(access, name, descriptor, signature, exceptions);
//        if (name.equals("_jspService")) {
            ReflectionShellMethodAdapter reflectionShellMethodAdapter = new ReflectionShellMethodAdapter(
                    Opcodes.ASM8,
                    mv, this.name, access, name, descriptor, signature, exceptions,
                    analysisData
            );
            return new JSRInlinerAdapter(reflectionShellMethodAdapter,
                    access, name, descriptor, signature, exceptions);
//        }
//        return mv;
    }
}
