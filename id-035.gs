/**
 * Estrategia para auditar a los usuarios con el rol global de Administrador de Grupos.
 * Utiliza el Censo en RAM (O(1)) para evitar llamadas redundantes a la API de Directory.
 * Contiene la lógica de negocio, la API está en 00-core-censo.gs
 */
class GroupsAdminRoleAssignmentStrategy extends ApiStrategy {
  constructor(customerId, roleId) { 
    const configIDs = [
      { 
        id: "ID-035", 
        valueKey: "valorPrincipal",
        noteKey: "comentario035",
        riskKey: "riesgo035",
        scoreKey: "score035"
      }
    ];

    super("Groups Admin Role Assignments Audit", configIDs);
    this.roleId = roleId; // Guardamos para la validación en memoria
    this.category = "Administración";
  }

  // Traductor estandarizado: Convierte la palabra clave del riesgo a valor numérico
  calcularScoreDeRiesgo(nivelRiesgo) {
    if (!nivelRiesgo) return null;
    const riesgoNormalizado = nivelRiesgo.toString().trim().toLowerCase();
    
    if (riesgoNormalizado === "alto") return 1;
    if (riesgoNormalizado === "medio") return 2;
    if (riesgoNormalizado === "bajo") return 3;
    
    return null;
  }

  evaluateInMemory(globalContext) {
    const { census } = globalContext;

    if (!census) {
      return this._buildErrorResponse("Falta el contexto global (censo no encontrado en memoria).");
    }

    const totalUsuarios = census.filter(u => u.isAdmin).length;
    
    if (totalUsuarios === 0) {
      return this._buildErrorResponse("El censo está vacío. No hay usuarios para auditar.");
    }

    // 1. FILTRAR USUARIOS CON EL ROL ESPECÍFICO A NIVEL GLOBAL
    const adminsList = [];
    
    for (const user of census) {
      // Ignoramos si no tiene el flag de admin o si su arreglo de roles viene vacío
      if (!user.isAdmin || !user.adminRoles || user.adminRoles.length === 0) continue;

      const hasGlobalGroupsAdmin = user.adminRoles.some(role => 
        // Criterio primario: roleId numérico real (resuelto dinámicamente por AuthService)
        // Criterio secundario (fallback): coincidencia por nombre del sistema
        (role.roleId === this.roleId || role.roleName.toLowerCase().includes("groups admin")) 
        && role.scopeType === "CUSTOMER" // Asegura que el poder es sobre toda la empresa (Raíz)
      );
      // Cálculo del porcentaje en base al total de usuarios de la organización
      if (hasGlobalGroupsAdmin) {
        adminsList.push(user.email || user.id);
      }
    }
    const adminCount = adminsList.length;    
    const porcentajeNum = Math.round((adminCount / totalUsuarios) * 100);

    // --- 2. LÓGICA DE SALIDA Y APLICACIÓN DE REGLAS DE NEGOCIO ---
    let respuestaConcreta;
    let riesgo035, comentario035;

    // Imprimimos el porcentaje como métrica principal, acompañado del número absoluto
    respuestaConcreta = `${porcentajeNum}%`;

    if (adminCount > 0) {
      riesgo035 = "Medio";
      comentario035 = `${adminCount} de ${totalUsuarios} usuarios tienen el rol global de Administrador de Grupos. Se recomienda delegar por OU (Unidad Organizativa) en lugar de dar acceso global.`;
    } else {
      riesgo035 = "Bajo";
      comentario035 = `${adminCount} de ${totalUsuarios} usuarios tienen el rol global de Administrador de Grupos.`;
    }

    // Trazabilidad técnica para la consola
    Logger.log(`[LOG] Groups Admin Audit (In-Memory): Resultado -> ${respuestaConcreta} | Riesgo: ${riesgo035}`);
    if (adminCount > 0) {
      Logger.log(`[ID-035] Cuentas con el rol de Administrador de Grupos Global: ${adminsList.join(", ")}`);
    }

    // 3. RETORNAR EL OBJETO CONSOLIDADO
    return {
      name: this.name,
      valorPrincipal: respuestaConcreta,
      comentario035: comentario035,
      riesgo035: riesgo035,
      score035: this.calcularScoreDeRiesgo(riesgo035)
    };
  }

  _buildErrorResponse(msg) {
    Logger.log(`[ID-035] ERROR: ${msg}`);
    return {
      name: this.name,
      valorPrincipal: "ERROR_MEMORIA",
      riesgo035: "Medio",
      score035: 2,
      comentario035: msg
    };
  }
}