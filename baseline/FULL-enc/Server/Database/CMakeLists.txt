aux_source_directory(. DATABASE_SRC)

add_library(DatabaseCore ${DATABASE_SRC})

target_link_libraries(DatabaseCore CommCore)