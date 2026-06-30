/**
 * Estrategia para auditar a los usuarios con el rol global de Administrador de Servicios.
 * Utiliza el Censo en RAM (O(1)) para evitar llamadas redundantes a la API de Directory.
 * Contiene la lógica de negocio para ID-038.
 */
class ServicesAdminRoleStrategy extends ApiStrategy {
  constructor(customerId, roleId) { 
    const configIDs = [
      { 
        id: "ID-038", 
        valueKey: "valorPrincipal",
        noteKey: "comentario038",
        riskKey: "riesgo038",
        scoreKey: "score038"
      }
    ];

    super("Services Admin Role Assignments Audit", configIDs);
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

    // Basamos el conteo en el total de administradores (como se ajustó en ID-035)
    const totalAdmins = census.filter(u => u.isAdmin).length;
    
    if (totalAdmins === 0) {
      return this._buildErrorResponse("El censo no contiene usuarios administradores para auditar.");
    }

    // 1. FILTRAR USUARIOS CON EL ROL ESPECÍFICO A NIVEL GLOBAL
    const adminsList = [];
    
    for (const user of census) {
      // Ignoramos si no tiene el flag de admin o si su arreglo de roles viene vacío
      if (!user.isAdmin || !user.adminRoles || user.adminRoles.length === 0) continue;

      const hasGlobalServicesAdmin = user.adminRoles.some(role => 
        // Criterio primario: roleId numérico real (resuelto dinámicamente por AuthService)
        // Criterio secundario (fallback): coincidencia por nombre del sistema
        (role.roleId === this.roleId || role.roleName.toLowerCase().includes("services admin")) 
        && role.scopeType === "CUSTOMER" // Asegura que el poder es sobre toda la empresa (Raíz)
      );
      
      if (hasGlobalServicesAdmin) {
        adminsList.push(user.email || user.id);
      }
    }
    
    const adminCount = adminsList.length;    
    const porcentajeNum = Math.round((adminCount / totalAdmins) * 100);

    // --- 2. LÓGICA DE SALIDA Y APLICACIÓN DE REGLAS DE NEGOCIO ---
    let respuestaConcreta;
    let riesgo038, comentario038;

    // Imprimimos el porcentaje como métrica principal, acompañado del número absoluto
    respuestaConcreta = `${porcentajeNum}%`;

    if (adminCount > 0) {
      riesgo038 = "Medio";
      comentario038 = `ATENCIÓN: ${adminCount} de ${totalAdmins} administradores tienen el rol global de Administrador de Servicios. Este rol permite gestionar la configuración y permisos de los servicios principales y adicionales en todo el dominio. Se recomienda revisar estas cuentas siguiendo el principio de menor privilegio.`;
    } else {
      riesgo038 = "Bajo";
      comentario038 = `Postura segura. ${adminCount} de ${totalAdmins} administradores tienen el rol global de Administrador de Servicios. No hay usuarios delegados con control global sobre las configuraciones de servicios.`;
    }

    // Trazabilidad técnica para la consola
    Logger.log(`[LOG] Services Admin Audit (In-Memory): Resultado -> ${respuestaConcreta} | Riesgo: ${riesgo038}`);
    if (adminCount > 0) {
      Logger.log(`[ID-038] Cuentas con el rol de Administrador de Servicios Global: ${adminsList.join(", ")}`);
    }

    // 3. RETORNAR EL OBJETO CONSOLIDADO
    return {
      name: this.name,
      valorPrincipal: respuestaConcreta,
      comentario038: comentario038,
      riesgo038: riesgo038,
      score038: this.calcularScoreDeRiesgo(riesgo038)
    };
  }

  _buildErrorResponse(msg) {
    Logger.log(`[ID-038] ERROR: ${msg}`);
    return {
      name: this.name,
      valorPrincipal: "ERROR_MEMORIA",
      riesgo038: "Medio",
      score038: 2,
      comentario038: msg
    };
  }
}