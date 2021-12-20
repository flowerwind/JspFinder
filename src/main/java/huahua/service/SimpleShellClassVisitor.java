package huahua.service;

import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.commons.JSRInlinerAdapter;

import java.util.HashMap;
import java.util.Map;

public class SimpleShellClassVisitor extends ClassVisitor {
    private final Map<String, Object> analysisData;

    private String name;
    private String signature;
    private String superName;
    private String[] interfaces;

    public SimpleShellClassVisitor() {
        super(Opcodes.ASM8);
        this.analysisData = new HashMap<>();
    }


    public Map<String, Object> getAnalysisData() {
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
        SimpleShellMethodAdapter simpleShellMethodAdapter = new SimpleShellMethodAdapter(
                Opcodes.ASM8,
                mv, this.name, access, name, descriptor, signature, exceptions,
                analysisData
        );
        return new JSRInlinerAdapter(simpleShellMethodAdapter,
                access, name, descriptor, signature, exceptions);
    }
}
