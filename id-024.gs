/**
 * Estrategia de Auditoría del Programa de Protección Avanzada (Titanium) para Administradores.
 * Propósito: Verificar si las cuentas críticas están blindadas contra ataques de phishing dirigidos.
 * Utiliza: Censo en RAM (Directory API).
 */
class SuperAdminSecurityStrategy extends ApiStrategy {
  constructor(customerId) {
    const configIDs = [
      { 
        id: "ID-024", 
        valueKey: "valorPrincipal", // Entregará el porcentaje (Ej: "80%")
        noteKey: "comentario024",
        riskKey: "riesgo024",
        scoreKey: "score024"
      }
    ];

    super("SuperAdmin APP (Titanium) Protection Audit", configIDs);
    this.customerId = customerId || "my_customer";
    this.category = "Identidad y autenticación";
  }

  evaluateInMemory(globalContext) {
    const { census } = globalContext;

    if (!census) {
      return this._buildErrorResponse("Falta el contexto global (censo no encontrado en memoria).");
    }

    // =======================================================================
    // PASO 1: AISLAR A LOS ADMINISTRADORES
    // =======================================================================
    const administradores = census.filter(user => user.isAdmin === true);
    const totalAdmins = administradores.length;

    if (totalAdmins === 0) {
      Logger.log("[ID-024] AVISO: El censo no reporta cuentas con privilegios de administrador.");
      return {
        name: this.name,
        valorPrincipal: "Sin administradores",
        comentario024: "El censo extraído de la Directory API no identificó cuentas con el rol de administrador activo, impidiendo calcular la métrica de protección.",
        riesgo024: "Medio",
        score024: this.calcularScoreDeRiesgo("Medio")
      };
    }

    Logger.log(`[ID-024] Auditando protección Titanium en ${totalAdmins} cuenta(s) de administrador...`);

    // =======================================================================
    // PASO 2: EVALUACIÓN DE PROTECCIÓN POR HARDWARE
    // =======================================================================
    let adminsProtegidos = 0;
    let adminsSinProteccion = []; // Guardamos los vulnerables para el log forense

    for (const admin of administradores) {
      // isEnrolledInApp es provisto nativamente por Directory API (Ver core-censo.gs)
      if (admin.isEnrolledInApp === true) {
        adminsProtegidos++;
      } else {
        adminsSinProteccion.push(admin.email);
      }
    }

    const porcentajeNum = Math.round((adminsProtegidos / totalAdmins) * 100);
    const respuestaConcreta = `${porcentajeNum}%`; // Ej: "100%"

    // =======================================================================
    // PASO 3: ASIGNACIÓN DE RIESGOS (TOLERANCIA CERO)
    // En administradores, CUALQUIER adopción menor a 100% es riesgo ALTO.
    // =======================================================================
    let riesgo024, comentario024;

    if (porcentajeNum === 0) {
      riesgo024 = "Alto";
      comentario024 = "Ningún usuario con privilegios de administrador está inscrito en el Programa de Protección Avanzada.";
    } else if (porcentajeNum === 100) {
      riesgo024 = "Bajo";
      comentario024 = "El 100% de las cuentas con privilegios de administrador operan bajo el blindaje del Programa de Protección Avanzada.";
    } else {
      riesgo024 = "Alto";
      comentario024 = `Solo el ${porcentajeNum}% de los administradores opera bajo el blindaje de Protección Avanzada.`;
    }

    // Trazabilidad forense para el auditor
    if (adminsSinProteccion.length > 0) {
      Logger.log(`[ID-024 ALERTA FORENSE] SuperAdmins expuestos a phishing (Sin APP): ${adminsSinProteccion.join(", ")}`);
    }

    Logger.log(`[ID-024] Protección APP en Admins: ${adminsProtegidos}/${totalAdmins} protegidos (${respuestaConcreta}) | Riesgo: ${riesgo024}`);

    // =======================================================================
    // PASO 4: RETORNAR RESULTADO
    // =======================================================================
    return {
      name: this.name,
      valorPrincipal: respuestaConcreta,
      comentario024: comentario024,
      riesgo024: riesgo024,
      score024: this.calcularScoreDeRiesgo(riesgo024)
    };
  }

  // Traductor de texto a número (Score)
  calcularScoreDeRiesgo(nivelRiesgo) {
    if (!nivelRiesgo) return "";
    const riesgoNormalizado = nivelRiesgo.toString().trim().toLowerCase();
    if (riesgoNormalizado === "alto") return 1;
    if (riesgoNormalizado === "medio") return 2;
    if (riesgoNormalizado === "bajo") return 3;
    return "";
  }

  // Handler de errores en memoria
  _buildErrorResponse(msg) {
    Logger.log(`[ID-024] ERROR: ${msg}`);
    return {
      name: this.name,
      valorPrincipal: "ERROR EN MEMORIA",
      riesgo024: "",
      score024: "",
      comentario024: msg
    };
  }
}